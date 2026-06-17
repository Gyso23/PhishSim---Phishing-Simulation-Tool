"""
PhishSim Configuration File
===========================
Edit these settings before deploying to a new server.

You can also override most settings with environment variables.
"""
import os
import socket
from pathlib import Path

# ==============================================
# BASE PATHS (auto-detected, usually no changes needed)
# ==============================================
BASE_DIR = Path(__file__).parent.resolve()
DATA_DIR = BASE_DIR / 'data'
LOGS_DIR = BASE_DIR / 'logs'
SSL_DIR = BASE_DIR / 'ssl'

# ==============================================
# SERVER CONFIGURATION
# ==============================================
# Port the server will run on
SERVER_PORT = int(os.environ.get('PHISHSIM_PORT', 8083))

# HTTPS port (when running in HTTPS mode)
TEST_PORT_HTTPS = int(os.environ.get('PHISHSIM_HTTPS_PORT', 7444))

# Set this to your server's IP or domain name
# If not set, it will auto-detect the local IP
# Examples: "192.168.1.100", "phishsim.company.com", "10.0.0.50"
SERVER_HOST = os.environ.get('PHISHSIM_HOST', None)

# Protocol: "http" or "https"
SERVER_PROTOCOL = os.environ.get('PHISHSIM_PROTOCOL', 'https')

def get_local_ip():
    """Auto-detect the server's LAN IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def get_base_url():
    """Get the full base URL for tracking links."""
    host = SERVER_HOST or get_local_ip()
    # Use HTTPS on TEST_PORT_HTTPS for production
    if SERVER_PROTOCOL == 'https':
        return f"https://{host}:{TEST_PORT_HTTPS}"
    return f"{SERVER_PROTOCOL}://{host}:{SERVER_PORT}"

# This is the URL that will be used in phishing emails for tracking
# It MUST be accessible from the target's network
TRACKING_BASE_URL = os.environ.get('PHISHSIM_TRACKING_URL', None) or get_base_url()

# ==============================================
# SMTP CONFIGURATION (Email Sending)
# ==============================================
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'mail.example.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 25))
SMTP_USER = os.environ.get('SMTP_USER', 'alerts@example.com')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD', '')
SENDER_DISPLAY_NAME = os.environ.get('SENDER_DISPLAY_NAME', 'Microsoft Security Center')

# ==============================================
# EMAIL TEMPLATE DEFAULTS
# ==============================================
EMAIL_SUBJECT = os.environ.get('EMAIL_SUBJECT', 'Review These Messages - Quarantine Notification')

# ==============================================
# DATABASE
# ==============================================
DATABASE_PATH = DATA_DIR / 'campaigns.db'
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', f'sqlite:///{DATABASE_PATH}')

# ==============================================
# SECURITY
# ==============================================
# Secret key for sessions - set this to a random string in production!
# Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY = os.environ.get('SECRET_KEY', None)  # Will auto-generate if not set

# Default admin credentials (CHANGE THESE!)
DEFAULT_ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
DEFAULT_ADMIN_PASS = os.environ.get('ADMIN_PASS', 'admin123')

# ==============================================
# LOGGING
# ==============================================
LOG_FILE = LOGS_DIR / 'phishsim.log'
EMAIL_LOG_FILE = BASE_DIR / 'email_sender.log'
TOKEN_MAPPING_FILE = BASE_DIR / 'token_mapping.log'

# ==============================================
# FILE PATHS
# ==============================================
EMAILS_FILE = BASE_DIR / 'emails.txt'
IMAGES_DIR = BASE_DIR / 'email_images'

# Image files for email templates (relative to IMAGES_DIR)
IMAGES = {
    "logo": str(IMAGES_DIR / "Microsoft_Logo_512px.png")
}

# ==============================================
# PRINT CONFIGURATION (for debugging)
# ==============================================
def print_config():
    """Print current configuration for debugging."""
    print("\n" + "=" * 60)
    print("  PhishSim Configuration")
    print("=" * 60)
    print(f"  Base Directory:    {BASE_DIR}")
    print(f"  Server Port:       {SERVER_PORT}")
    print(f"  Server Host:       {SERVER_HOST or 'auto-detect'}")
    print(f"  Tracking URL:      {TRACKING_BASE_URL}")
    print(f"  SMTP Server:       {SMTP_SERVER}:{SMTP_PORT}")
    print(f"  SMTP User:         {SMTP_USER}")
    print(f"  Database:          {DATABASE_PATH}")
    print("=" * 60 + "\n")

if __name__ == '__main__':
    print_config()

# Add at the end of config.py
ADDITIONAL_USERS = {
    'security': 'hash_for_security_user',
    'manager': 'hash_for_manager_user',
}

# ==============================================
# ORGANIZATIONAL SBUs / SUBSIDIARIES
# ==============================================
# List of Strategic Business Units / Subsidiaries
# These will be pre-populated when adding historical campaign data
DEFAULT_SBUS = [
    "Department A",
    "Department B",
    "Department C",
]


