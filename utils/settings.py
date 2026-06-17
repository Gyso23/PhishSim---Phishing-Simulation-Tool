from flask import Blueprint, render_template, request, jsonify, session, redirect, url_for, send_from_directory, current_app
from functools import wraps
from .models import db, SystemSetting, SMTPProfile, Target
from pathlib import Path
import os
import importlib
import json
from datetime import datetime

# backups directory
BACKUPS_DIR = Path('backups')

settings_bp = Blueprint('settings', __name__, url_prefix='/settings')

# --------------------------------------------------------------------------
# Default reminder HTML template (used when no DB setting exists)
# --------------------------------------------------------------------------
_DEFAULT_REMINDER_TEMPLATE = '''<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; }
        .header { background: linear-gradient(135deg, #e94560, #c23a50); color: white; padding: 30px; text-align: center; }
        .content { padding: 30px; }
        .button { display: inline-block; background: #e94560; color: white; padding: 15px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; }
        .footer { padding: 20px; text-align: center; color: #666; font-size: 12px; background: #f9f9f9; }
        .warning-box { background: #fff3f3; border-left: 4px solid #e94560; padding: 15px; margin: 20px 0; }
        .red-text { color: #cc0000; font-weight: bold; }
        .reminder-note { background: #fff0f0; padding: 12px; border-radius: 4px; margin: 15px 0; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Alert: Phishing Link Detected</h1>
        </div>
        <div class="content">
            <div class="warning-box">
                <strong class="red-text">You clicked a phishing link.</strong>
            </div>
            <p>Our security systems have detected that you <strong>clicked</strong> on a known phishing link. This link has been blocked to protect your information.</p>
            <div class="reminder-note">
                <span class="red-text">Reminder: You will be prompted every 5 minutes until this security assessment is completed.</span>
            </div>
            <p>No credentials or personal data were compromised during this interaction. The threat has been neutralized.</p>
            <a href="{landing_page_url}" class="button">Complete Security Assessment Now</a>
        </div>
        <div class="footer">
            <p>Automated security notification | If you have questions, contact your system administrator</p>
        </div>
    </div>
</body>
</html>'''

_REMINDER_DEFAULTS = {
    'reminder_sender_name':    'Information Security',
    'reminder_sender_email':   '',
    'reminder_smtp_profile_id':'',
    'reminder_interval':       '5',
    'max_reminders':           '12',
    'reminder_subject':        '⚠️ REMINDER: Complete Your Security Assessment',
    'reminder_email_template': _DEFAULT_REMINDER_TEMPLATE,
}


def _seed_reminder_defaults():
    """Insert reminder default settings into the DB if they do not already exist."""
    changed = False
    for key, value in _REMINDER_DEFAULTS.items():
        if not SystemSetting.query.get(key):
            db.session.add(SystemSetting(key=key, value=value))
            changed = True
    if changed:
        db.session.commit()
# --------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


def _is_admin():
    """Runtime admin check to avoid circular imports with app.py.

    Imports ADMIN_USERS from app at request time (when app is fully loaded).
    """
    user = session.get('user')
    if not user:
        return False
    try:
        from app import ADMIN_USERS
        return user in ADMIN_USERS
    except Exception:
        # Fallback conservative check
        return user == 'admin'

@settings_bp.route('/', methods=['GET'])
@login_required
def settings_page():
    """Render the settings page."""
    _seed_reminder_defaults()
    settings = {s.key: s.value for s in SystemSetting.query.all()}
    smtp_profiles = SMTPProfile.query.all()
    return render_template('settings.html', settings=settings, smtp_profiles=smtp_profiles)

@settings_bp.route('/update', methods=['POST'])
@login_required
def update_settings():
    data = request.get_json()
    
    try:
        for key, value in data.items():
            setting = SystemSetting.query.get(key)
            if setting:
                setting.value = str(value)
            else:
                setting = SystemSetting(key=key, value=str(value))
                db.session.add(setting)
        
        db.session.commit()
        return jsonify({'success': True, 'message': 'Settings updated successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500

@settings_bp.route('/get_defaults', methods=['GET'])
def get_defaults():
    """API to get default settings for other parts of the app."""
    if 'user' not in session:
        return redirect(url_for('login', next=request.url))
    if not _is_admin():
        return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
    settings = {s.key: s.value for s in SystemSetting.query.all()}
    return jsonify(settings)


@settings_bp.route('/backups', methods=['GET'])
def backups_page():
    if 'user' not in session:
        return redirect(url_for('login', next=request.url))
    if not _is_admin():
        return redirect(url_for('settings_page'))
    return render_template('backups.html')


@settings_bp.route('/backups/list', methods=['GET'])
def backups_list():
    if 'user' not in session:
        return redirect(url_for('login', next=request.url))
    if not _is_admin():
        return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
    """Return JSON list of backup files in the backups directory."""
    files = []
    for p in sorted(BACKUPS_DIR.glob('*.zip'), key=lambda x: x.stat().st_mtime, reverse=True):
        stat = p.stat()
        files.append({
            'name': p.name,
            'path': str(p),
            'size': stat.st_size,
            'modified': datetime.utcfromtimestamp(stat.st_mtime).isoformat() + 'Z'
        })
    return jsonify(files)
@settings_bp.route('/backups/preview/<path:filename>', methods=['GET'])
def backups_preview(filename):
    if 'user' not in session:
        return redirect(url_for('login', next=request.url))
    safe_name = Path(filename).name
    zip_path = BACKUPS_DIR / safe_name
    if not zip_path.exists():
        return "Backup not found", 404

    try:
        import zipfile as _zf
        import collections
        with _zf.ZipFile(zip_path, 'r') as zf:
            entries = set(zf.namelist())

            def _read_table(t):
                entry = f'tables/{t}.json'
                if entry in entries:
                    with zf.open(entry) as fh:
                        return json.loads(fh.read().decode('utf-8'))
                return []

            campaigns_raw = _read_table('campaigns')
            results_raw = _read_table('results')
            targets_raw = _read_table('targets')
            questionnaire_raw = _read_table('questionnaire_responses')
    except Exception as e:
        current_app.logger.exception('Error reading backup preview')
        return f"Error reading backup: {e}", 500

    # Index results and targets by campaign_id
    result_map = collections.defaultdict(list)
    for r in results_raw:
        result_map[r.get('campaign_id')].append(r)
    target_map = collections.defaultdict(list)
    for t in targets_raw:
        target_map[t.get('campaign_id')].append(t)

    total_sent = total_opened = total_clicked = total_compromised = total_reported = 0

    campaign_data = []
    for c in campaigns_raw:
        cid = c.get('id')
        c_results = result_map.get(cid, [])
        sent = sum(1 for r in c_results if r.get('sent'))
        opened = sum(1 for r in c_results if r.get('opened'))
        clicked = sum(1 for r in c_results if r.get('clicked'))
        reported = sum(1 for r in c_results if r.get('reported'))
        compromised = sum(1 for r in c_results if r.get('clicked') and not r.get('reported'))
        submitted = sum(1 for r in c_results if r.get('submitted'))
        q_done = sum(1 for r in c_results if r.get('questionnaire_completed'))
        avg_score = None
        scores = [r.get('questionnaire_score') for r in c_results if r.get('questionnaire_score') is not None]
        if scores:
            avg_score = round(sum(scores) / len(scores), 1)
        total_sent += sent
        total_opened += opened
        total_clicked += clicked
        total_compromised += compromised
        total_reported += reported
        c['_sent'] = sent
        c['_opened'] = opened
        c['_clicked'] = clicked
        c['_reported'] = reported
        c['_compromised'] = compromised
        c['_submitted'] = submitted
        c['_q_done'] = q_done
        c['_avg_score'] = avg_score
        c['_total'] = len(c_results)
        c['_results'] = c_results
        c['_targets'] = target_map.get(cid, [])
        campaign_data.append(c)

    stat = zip_path.stat()
    backup_date = datetime.utcfromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M UTC')

    return render_template(
        'backup_preview.html',
        backup_name=safe_name,
        backup_date=backup_date,
        campaigns=campaign_data,
        total_campaigns=len(campaigns_raw),
        total_targets=len(targets_raw),
        total_results=len(results_raw),
        total_sent=total_sent,
        total_opened=total_opened,
        total_clicked=total_clicked,
        total_compromised=total_compromised,
        total_reported=total_reported,
    )


_WKHTMLTOPDF = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'


@settings_bp.route('/backups/export_pdf/<path:filename>', methods=['GET'])
def backups_export_pdf(filename):
    """Export a backup preview page as a PDF."""
    if 'user' not in session:
        return redirect(url_for('login', next=request.url))
    import subprocess, tempfile, os as _os
    from flask import Response
    safe_name = Path(filename).name
    zip_path = BACKUPS_DIR / safe_name
    if not zip_path.exists():
        return "Backup not found", 404
    if not _os.path.exists(_WKHTMLTOPDF):
        return "wkhtmltopdf not installed", 500
    try:
        preview_url = url_for('settings.backups_preview', filename=safe_name, _external=True)
        session_cookie = request.cookies.get('session', '')
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tf:
            out_path = tf.name
        cmd = [
            _WKHTMLTOPDF,
            '--page-size', 'A3',
            '--orientation', 'Landscape',
            '--margin-top', '10mm', '--margin-bottom', '10mm',
            '--margin-left', '10mm', '--margin-right', '10mm',
            '--print-media-type',
            '--no-background',
            '--cookie', 'session', session_cookie,
            '--javascript-delay', '1000',
            '--quiet',
            preview_url,
            out_path,
        ]
        result = subprocess.run(cmd, capture_output=True, timeout=120)
        if result.returncode != 0:
            err = result.stderr.decode('utf-8', errors='replace')
            current_app.logger.error(f'wkhtmltopdf error: {err}')
            return f'PDF generation failed: {err}', 500
        with open(out_path, 'rb') as fh:
            pdf_bytes = fh.read()
        _os.unlink(out_path)
        stem = Path(safe_name).stem
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="{stem}_report.pdf"'}
        )
    except subprocess.TimeoutExpired:
        return 'PDF export timed out', 504
    except Exception as e:
        current_app.logger.exception('Backup PDF export error')
        return str(e), 500


@settings_bp.route('/backups/create', methods=['POST'])
def backups_create():
    if 'user' not in session:
        return redirect(url_for('login', next=request.url))
    if not _is_admin():
        return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
    """Create a new backup by invoking tools.backup_campaigns.make_backup."""
    try:
        # import the backup helper
        backup_mod = importlib.import_module('tools.backup_campaigns')
        db_path = request.json.get('db') if request.json else None
        db_path = Path(db_path) if db_path else Path('data/campaigns.db')
        out = request.json.get('out') if request.json else None
        out_path = Path(out) if out else None

        zpath, counts = backup_mod.make_backup(db_path, out_path)
        return jsonify({'success': True, 'backup': str(zpath), 'counts': counts})
    except Exception as e:
        current_app.logger.exception('Error creating backup')
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_bp.route('/backups/upload', methods=['POST'])
def backups_upload():
    if 'user' not in session:
        return redirect(url_for('login', next=request.url))
    if not _is_admin():
        return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
    """Upload a backup zip file into the backups directory via the web UI."""
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400
    # sanitize filename
    filename = Path(file.filename).name
    if not filename.lower().endswith('.zip'):
        return jsonify({'success': False, 'error': 'Only .zip files are allowed'}), 400

    dest = BACKUPS_DIR / filename
    # avoid overwrite
    if dest.exists():
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        dest = BACKUPS_DIR / f"{dest.stem}_{ts}.zip"

    try:
        file.save(str(dest))
        return jsonify({'success': True, 'name': dest.name})
    except Exception as e:
        current_app.logger.exception('Error saving uploaded backup')
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_bp.route('/backups/download/<path:filename>', methods=['GET'])
def backups_download(filename):
    if 'user' not in session:
        return redirect(url_for('login', next=request.url))
    if not _is_admin():
        return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
    """Download a backup file."""
    safe_path = BACKUPS_DIR / Path(filename).name
    if not safe_path.exists():
        return jsonify({'error': 'Not found'}), 404
    return send_from_directory(str(BACKUPS_DIR.resolve()), safe_path.name, as_attachment=True)


@settings_bp.route('/backups/delete', methods=['POST'])
def backups_delete():
    if 'user' not in session:
        return redirect(url_for('login', next=request.url))
    if not _is_admin():
        return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
    data = request.get_json() or {}
    name = data.get('name')
    if not name:
        return jsonify({'success': False, 'error': 'Missing name'}), 400
    path = BACKUPS_DIR / Path(name).name
    if not path.exists():
        return jsonify({'success': False, 'error': 'Not found'}), 404
    try:
        path.unlink()
        return jsonify({'success': True})
    except Exception as e:
        current_app.logger.exception('Error deleting backup')
        return jsonify({'success': False, 'error': str(e)}), 500


@settings_bp.route('/backups/restore', methods=['POST'])
def backups_restore():
    if 'user' not in session:
        return redirect(url_for('login', next=request.url))
    if not _is_admin():
        return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
    """Restore a backup. By default writes restored DB to data/campaigns_restored_<ts>.db.
    To replace live DB pass replace_live=true in JSON (dangerous).
    """
    data = request.get_json() or {}
    name = data.get('name')
    replace_live = bool(data.get('replace_live'))
    if not name:
        return jsonify({'success': False, 'error': 'Missing name'}), 400
    zip_path = BACKUPS_DIR / Path(name).name
    if not zip_path.exists():
        return jsonify({'success': False, 'error': 'Not found'}), 404

    try:
        restore_mod = importlib.import_module('tools.restore_campaigns')
        if replace_live:
            dest = Path('data/campaigns.db')
        else:
            ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
            dest = Path(f'data/campaigns_restored_{ts}.db')

        restored = restore_mod.extract_db_from_zip(zip_path, dest)
        return jsonify({'success': True, 'restored_to': str(restored)})
    except Exception as e:
        current_app.logger.exception('Error restoring backup')
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================================
#  SBU Management
# ============================================================

def _load_sbu_list():
    """Load SBU list from SystemSetting, falling back to DEFAULT_SBUS from config."""
    setting = SystemSetting.query.get('sbu_list')
    if setting and setting.value:
        try:
            return json.loads(setting.value)
        except Exception:
            pass
    try:
        from config import DEFAULT_SBUS
        return list(DEFAULT_SBUS)
    except ImportError:
        return []


def _save_sbu_list(sbus):
    """Persist the SBU list to SystemSetting."""
    setting = SystemSetting.query.get('sbu_list')
    if setting:
        setting.value = json.dumps(sbus)
    else:
        db.session.add(SystemSetting(key='sbu_list', value=json.dumps(sbus), description='Configured SBU list'))
    db.session.commit()


@settings_bp.route('/sbus', methods=['GET'])
@login_required
def sbu_management_page():
    """SBU management page — add, rename and delete SBUs."""
    sbus = _load_sbu_list()
    return render_template('sbu_management.html', sbus=sbus)


@settings_bp.route('/sbus/add', methods=['POST'])
@login_required
def sbu_add():
    """Add a new SBU to the list."""
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'SBU name is required'}), 400
    sbus = _load_sbu_list()
    if name in sbus:
        return jsonify({'success': False, 'error': 'SBU already exists'}), 409
    sbus.append(name)
    _save_sbu_list(sbus)
    return jsonify({'success': True, 'sbus': sbus})


@settings_bp.route('/sbus/rename', methods=['POST'])
@login_required
def sbu_rename():
    """Rename an SBU and update all targets that have the old name."""
    data = request.get_json(silent=True) or {}
    old_name = (data.get('old_name') or '').strip()
    new_name = (data.get('new_name') or '').strip()
    if not old_name or not new_name:
        return jsonify({'success': False, 'error': 'Both old_name and new_name are required'}), 400
    if old_name == new_name:
        return jsonify({'success': False, 'error': 'Names are identical'}), 400

    sbus = _load_sbu_list()
    if old_name not in sbus:
        return jsonify({'success': False, 'error': f'SBU "{old_name}" not found'}), 404
    if new_name in sbus:
        return jsonify({'success': False, 'error': f'SBU "{new_name}" already exists'}), 409

    # Rename in list
    sbus[sbus.index(old_name)] = new_name
    _save_sbu_list(sbus)

    # Update all targets that carry the old SBU name
    updated = Target.query.filter_by(sbu=old_name).update({Target.sbu: new_name}, synchronize_session=False)
    db.session.commit()

    return jsonify({'success': True, 'sbus': sbus, 'targets_updated': updated})


@settings_bp.route('/sbus/delete', methods=['POST'])
@login_required
def sbu_delete():
    """Remove an SBU from the list. Targets keep their existing sbu value."""
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'success': False, 'error': 'SBU name is required'}), 400

    sbus = _load_sbu_list()
    if name not in sbus:
        return jsonify({'success': False, 'error': f'SBU "{name}" not found'}), 404

    sbus.remove(name)
    _save_sbu_list(sbus)
    # Count how many targets still carry this SBU (informational)
    count = Target.query.filter_by(sbu=name).count()
    return jsonify({'success': True, 'sbus': sbus, 'remaining_targets': count})


@settings_bp.route('/sbus/reorder', methods=['POST'])
@login_required
def sbu_reorder():
    """Replace the SBU list order with the provided ordered array."""
    data = request.get_json(silent=True) or {}
    new_order = data.get('sbus', [])
    if not isinstance(new_order, list):
        return jsonify({'success': False, 'error': 'sbus must be an array'}), 400
    _save_sbu_list([s.strip() for s in new_order if s.strip()])
    return jsonify({'success': True})

