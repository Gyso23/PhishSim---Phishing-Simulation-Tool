"""
Production server launcher for PhishSim

Behavior:
 - HTTPS enabled by default unless --http is passed.
 - Certificate files expected: certs/cert.pem and certs/key.pem (relative to project root).
 - If certs missing, generate_cert.py is executed via subprocess to create self-signed certs.
 - If generation fails, falls back to HTTP.
 - Use --port to override default port (uses TEST_PORT_HTTPS when HTTPS and available).
 - Single server (uvicorn) handles both HTTP and HTTPS modes.
 - Auto-reloads when any .py or .html file in the project directory changes (watchdog).
"""
import os
import sys
import socket
import subprocess
import logging
import warnings
import time
import signal
import threading
from pathlib import Path
import argparse

# ── Auto-reload watcher ───────────────────────────────────────────────────────
# When this script is run directly (not as a reloaded child), it spawns itself
# as a subprocess and restarts it whenever a watched file changes.
# The child process sets PHISHSIM_CHILD=1 so it runs the server directly.

WATCH_EXTENSIONS = {'.py', '.html', '.css', '.js'}
WATCH_DIRS = ['.']
IGNORE_DIRS = {'__pycache__', '.venv', 'venv', '.git', 'node_modules', 'backups', 'data', 'logs', 'certs', 'ssl'}

class _ChangeHandler:
    """Simple polling-based file change detector."""
    def __init__(self, root: Path):
        self.root = root
        self._snapshot = self._take_snapshot()

    def _take_snapshot(self):
        snap = {}
        for path in self.root.rglob('*'):
            if any(part in IGNORE_DIRS for part in path.parts):
                continue
            if path.suffix in WATCH_EXTENSIONS and path.is_file():
                try:
                    snap[path] = path.stat().st_mtime
                except OSError:
                    pass
        return snap

    def has_changed(self):
        new_snap = self._take_snapshot()
        if new_snap != self._snapshot:
            # Find what changed for logging
            changed = []
            for p, mtime in new_snap.items():
                if self._snapshot.get(p) != mtime:
                    changed.append(str(p.relative_to(self.root)))
            for p in self._snapshot:
                if p not in new_snap:
                    changed.append(f"[deleted] {p.relative_to(self.root)}")
            self._snapshot = new_snap
            return changed
        return []


def _run_watcher(child_args: list):
    """Spawn the server child and restart it on file changes."""
    root = Path(__file__).parent.resolve()
    watcher = _ChangeHandler(root)
    child = None

    def start_child():
        env = os.environ.copy()
        env['PHISHSIM_CHILD'] = '1'
        return subprocess.Popen([sys.executable] + child_args, env=env)

    print("👁  Auto-reload watcher active. Watching for changes to .py / .html / .css / .js files.")
    print("   Press Ctrl+C to stop.\n")

    child = start_child()

    try:
        while True:
            time.sleep(1)

            # Check if child died unexpectedly
            ret = child.poll()
            if ret is not None:
                print(f"\n⚠️  Server exited with code {ret}. Restarting in 2 seconds...")
                time.sleep(2)
                child = start_child()
                watcher._snapshot = watcher._take_snapshot()
                continue

            # Check for file changes
            changed = watcher.has_changed()
            if changed:
                print(f"\n🔄 Change detected in: {', '.join(changed[:3])}{'...' if len(changed) > 3 else ''}")
                print("   Restarting server...")
                # Gracefully terminate child
                try:
                    child.terminate()
                    child.wait(timeout=5)
                except Exception:
                    try:
                        child.kill()
                    except Exception:
                        pass
                time.sleep(0.5)
                child = start_child()
                print("   ✅ Server restarted.\n")

    except KeyboardInterrupt:
        print("\n⛔ Shutting down...")
        try:
            child.terminate()
            child.wait(timeout=5)
        except Exception:
            try:
                child.kill()
            except Exception:
                pass
        sys.exit(0)

# ─────────────────────────────────────────────────────────────────────────────

# Suppress asyncio connection reset errors on Windows BEFORE importing uvicorn
# These occur when browser abruptly closes SSL connections
class ConnectionResetFilter(logging.Filter):
    def filter(self, record):
        msg = str(record.getMessage()) if record.msg else ''
        # Filter out common Windows socket reset errors
        suppress_patterns = [
            'ConnectionResetError',
            'WinError 10054',
            '_call_connection_lost',
            'forcibly closed by the remote host',
            'An existing connection was forcibly closed',
            'Exception in callback',
            '_ProactorBasePipeTransport'
        ]
        for pattern in suppress_patterns:
            if pattern in msg:
                return False
        return True

# Apply filter to all relevant loggers BEFORE they're used
for logger_name in ['', 'asyncio', 'uvicorn', 'uvicorn.error', 'uvicorn.access']:
    logger = logging.getLogger(logger_name)
    logger.addFilter(ConnectionResetFilter())

# Suppress specific warnings
warnings.filterwarnings('ignore', message='.*forcibly closed.*')

# Now import uvicorn
import uvicorn
from asgiref.wsgi import WsgiToAsgi

# Import configuration (best-effort)
try:
    from config import (
        SERVER_PORT, SERVER_HOST, 
        TEST_PORT_HTTPS, get_local_ip, get_base_url, print_config,
        SERVER_PROTOCOL
    )
    USE_CONFIG = True
except Exception:
    USE_CONFIG = False
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    SERVER_PORT = 8082
    SERVER_HOST = None
    TEST_PORT_HTTPS = 7443
    SERVER_PROTOCOL = 'https'

def check_ssl_certificates():
    """Check if SSL certificates exist"""
    cert_file = Path("certs/cert.pem")
    key_file = Path("certs/key.pem")
    return cert_file.exists() and key_file.exists()

def generate_certificates():
    """Generate SSL certificates if they don't exist"""
    print("🔐 SSL certificates not found. Generating self-signed certificate...")
    print()
    try:
        result = subprocess.run(
            [sys.executable, "generate_cert.py"], 
            capture_output=False, 
            text=True
        )
        if result.returncode == 0:
            return check_ssl_certificates()
        else:
            return False
    except Exception as e:
        print(f"❌ Failed to generate certificates: {e}")
        return False

def parse_args():
    parser = argparse.ArgumentParser(description="Run PhishSim production server")
    parser.add_argument('--http', action='store_true', help='Force HTTP (disable HTTPS)')
    parser.add_argument('--port', type=int, help='Override server port')
    parser.add_argument('--host', help='Override host to bind')
    parser.add_argument('--reset-past-targets', action='store_true', help='Reset all targets past_target flag (new year)')
    return parser.parse_args()

if __name__ == '__main__':
    # ── Auto-reload: if we are not the child worker, launch the watcher ──────
    if os.environ.get('PHISHSIM_CHILD') != '1':
        # Pass all original CLI arguments to the child
        _run_watcher([__file__] + sys.argv[1:])
        sys.exit(0)
    # ─────────────────────────────────────────────────────────────────────────

    args = parse_args()

    if args.reset_past_targets:
        from utils.campaigns import reset_past_target_flags
        from utils.models import db
        print("Resetting all targets' past_target flag...")
        # Import app here so we can use the Flask app context for DB changes
        from app import app
        with app.app_context():
            updated = reset_past_target_flags()
        print(f"✅ Reset complete. {updated} targets updated.")
        sys.exit(0)

    # Determine host and port
    host = args.host or (SERVER_HOST or get_local_ip())

    if args.port:
        port = int(args.port)
    else:
        # Prefer HTTPS test port when running HTTPS
        if not args.http:
            port = int(TEST_PORT_HTTPS if 'TEST_PORT_HTTPS' in globals() else 7443)
        else:
            port = int(SERVER_PORT if 'SERVER_PORT' in globals() else 8082)

    protocol = 'http' if args.http else 'https'

    # Check SSL availability when HTTPS requested
    ssl_cert = Path('certs/cert.pem')
    ssl_key = Path('certs/key.pem')
    if protocol == 'https':
        if not check_ssl_certificates():
            print('⚠️  SSL certificates missing. Falling back to HTTP on standard port.')
            protocol = 'http'
            if not args.port:
                port = int(SERVER_PORT if 'SERVER_PORT' in globals() else 8083)
    
    # Quick port availability check (bind to all interfaces for the port)
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        test_sock.bind(('', port))
        test_sock.close()
    except OSError as e:
        print(f"❌ Port {port} appears to be in use or unavailable: {e}")
        print("Please stop the process using that port or choose another port with --port.")
        sys.exit(1)

    # Import the Flask app only after we've done CLI handling and port checks to avoid
    # importing side-effects early when running management commands.
    try:
        from app import app
    except Exception as e:
        print(f"❌ Failed to import Flask app: {e}")
        raise

    # Wrap Flask app for ASGI server
    asgi_app = WsgiToAsgi(app)

    # Build uvicorn run arguments
    uvicorn_kwargs = {
        'host': host,
        'port': port,
        'log_level': 'info',
    }
    if protocol == 'https':
        uvicorn_kwargs['ssl_certfile'] = str(ssl_cert)
        uvicorn_kwargs['ssl_keyfile'] = str(ssl_key)

    print(f"Starting PhishSim on {protocol}://{host}:{port} (ssl={'yes' if protocol=='https' else 'no'})")

    try:
        uvicorn.run(asgi_app, **uvicorn_kwargs)
    except Exception as e:
        print(f"❌ Server failed to start: {e}")
        sys.exit(1)
