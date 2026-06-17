# Main Flask application. Tracking endpoints are provided by the tracking blueprint
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from functools import wraps
from utils.tracking import tracking_bp
from utils.campaigns import campaigns_bp
from utils.settings import settings_bp
from utils.template_routes import templates_bp
from utils.models import db as models_db
from utils.audit import log_audit, AuditActions, get_audit_logs
from datetime import timedelta, datetime
from collections import defaultdict
from utils.metrics import log_metric
import os
import hashlib
import secrets
import time

# Import configuration
try:
    from config import (
        SECRET_KEY, DATABASE_PATH, SQLALCHEMY_DATABASE_URI, DATA_DIR,
        DEFAULT_ADMIN_USER, DEFAULT_ADMIN_PASS, TRACKING_BASE_URL
    )
    USE_CONFIG = True
except ImportError:
    USE_CONFIG = False
    TRACKING_BASE_URL = None

app = Flask(__name__)
# Session configuration - use config, environment variable, or generate a secure key
if USE_CONFIG and SECRET_KEY:
    app.secret_key = SECRET_KEY
else:
    app.secret_key = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)  # Default session: 8 hours
app.config['REMEMBER_ME_DURATION'] = timedelta(days=30)  # Remember me: 30 days
app.register_blueprint(tracking_bp)
app.register_blueprint(campaigns_bp)
app.register_blueprint(settings_bp)
app.register_blueprint(templates_bp)

# Custom template filters
import json

@app.template_filter('from_json')
def from_json_filter(value):
    """Parse JSON string in templates."""
    if not value:
        return {}
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return {}

# ============== RATE LIMITING ==============
# Track login attempts: {ip: [(timestamp, username), ...]}
login_attempts = defaultdict(list)
RATE_LIMIT_WINDOW = 60  # seconds
MAX_ATTEMPTS = 5  # max attempts per window

def check_rate_limit(ip):
    """Check if IP has exceeded rate limit. Returns (allowed, remaining_seconds)."""
    now = time.time()
    # Clean old attempts
    login_attempts[ip] = [t for t in login_attempts[ip] if now - t < RATE_LIMIT_WINDOW]
    
    if len(login_attempts[ip]) >= MAX_ATTEMPTS:
        oldest = min(login_attempts[ip])
        wait_time = int(RATE_LIMIT_WINDOW - (now - oldest))
        return False, wait_time
    return True, 0

def record_login_attempt(ip):
    """Record a login attempt for rate limiting."""
    login_attempts[ip].append(time.time())
# ============================================


# ============== HELPER FUNCTIONS ==============
def get_target_for_result(result, campaign_id=None):
    """Get the Target for a Result, checking campaign-specific first, then global.
    
    This prevents duplication issues when the same email exists in both
    campaign-specific and global target tables.
    """
    from utils.models import Target
    
    # Use campaign_id from result if not provided
    cid = campaign_id or getattr(result, 'campaign_id', None)
    
    # First try to find campaign-specific target
    if cid:
        target = Target.query.filter_by(campaign_id=cid, email=result.email).first()
        if target:
            return target
    
    # Fall back to global target (campaign_id=None)
    return Target.query.filter_by(campaign_id=None, email=result.email).first()


def is_compromised(r):
    """Derived rule: a result is compromised if the user clicked but did NOT report.
    This is the single source of truth used everywhere in the app."""
    return bool(r.clicked) and not bool(getattr(r, 'reported', False))
# ============================================


# ============== ACCESS MANAGEMENT ==============
# Add authorized users here (username: password_hash)
# To generate a password hash, run: python -c "import hashlib; print(hashlib.sha256('yourpassword'.encode()).hexdigest())"
# You can also set ADMIN_USER and ADMIN_PASS environment variables or in config.py
if USE_CONFIG:
    AUTHORIZED_USERS = {
        DEFAULT_ADMIN_USER: hashlib.sha256(DEFAULT_ADMIN_PASS.encode()).hexdigest(),
    }
else:
    AUTHORIZED_USERS = {
        os.environ.get('ADMIN_USER', 'admin'): hashlib.sha256(os.environ.get('ADMIN_PASS', 'admin123').encode()).hexdigest(),
    }
# Add additional users if needed
# AUTHORIZED_USERS['security'] = hashlib.sha256('phishsim2024'.encode()).hexdigest()

ADMIN_USERS = {DEFAULT_ADMIN_USER} if USE_CONFIG else {'admin'}  # Users who can manage other users

def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin privileges."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
        if session['user'] not in ADMIN_USERS:
            return jsonify({'success': False, 'error': 'Admin privileges required'}), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page with rate limiting and remember me."""
    error = None
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    
    if request.method == 'POST':
        # Check rate limit
        allowed, wait_time = check_rate_limit(client_ip)
        if not allowed:
            log_audit(AuditActions.LOGIN_FAILED, details=f"Rate limited - too many attempts", success=False, user='rate_limited')
            error = f'Too many login attempts. Please wait {wait_time} seconds.'
            return render_template('login.html', error=error)
        
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        remember_me = request.form.get('remember_me') == 'on'
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Record attempt before checking credentials
        record_login_attempt(client_ip)
        
        if username in AUTHORIZED_USERS and AUTHORIZED_USERS[username] == password_hash:
            session['user'] = username
            session.permanent = True
            
            # Set longer session duration if "Remember Me" is checked
            if remember_me:
                app.permanent_session_lifetime = timedelta(days=30)
                session['remember_me'] = True
            else:
                app.permanent_session_lifetime = timedelta(hours=8)
            
            # Clear rate limit on successful login
            login_attempts[client_ip] = []
            
            log_audit(AuditActions.LOGIN_SUCCESS, details=f"User '{username}' logged in (remember_me={remember_me})", user=username)
            next_url = request.args.get('next') or url_for('dashboard')
            return redirect(next_url)
        else:
            log_audit(AuditActions.LOGIN_FAILED, details=f"Failed login attempt for '{username}'", success=False, user=username or 'unknown')
            attempts_left = MAX_ATTEMPTS - len(login_attempts[client_ip])
            if attempts_left <= 2:
                error = f'Invalid username or password. {attempts_left} attempts remaining.'
            else:
                error = 'Invalid username or password'
    
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    """Logout and clear session."""
    user = session.get('user', 'unknown')
    log_audit(AuditActions.LOGOUT, details=f"User '{user}' logged out", user=user)
    session.pop('user', None)
    session.pop('remember_me', None)
    return redirect(url_for('login'))

# ── Hosted image library ──────────────────────────────────────────────────────
# Images uploaded here are served publicly at /img/<filename> so they can be
# embedded in emails with a plain https:// URL that works in every mail client.

EMAIL_IMAGES_DIR = os.path.join(os.path.dirname(__file__), 'email_images')
os.makedirs(EMAIL_IMAGES_DIR, exist_ok=True)

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico'}
ALLOWED_IMAGE_MIMETYPES = {
    'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg',
    'gif': 'image/gif', 'svg': 'image/svg+xml', 'webp': 'image/webp',
    'ico': 'image/x-icon',
}

@app.route('/img/<path:filename>')
def serve_email_image(filename):
    """Publicly serve an image from the email_images/ folder (no login required)."""
    from flask import send_from_directory
    return send_from_directory(EMAIL_IMAGES_DIR, filename)

@app.route('/api/images', methods=['GET'])
@login_required
def list_email_images():
    """Return JSON list of all images in the email_images/ folder."""
    files = []
    for f in sorted(os.listdir(EMAIL_IMAGES_DIR)):
        if f.rsplit('.', 1)[-1].lower() in ALLOWED_IMAGE_EXTENSIONS:
            files.append({
                'filename': f,
                'url': request.host_url.rstrip('/') + '/img/' + f,
            })
    return jsonify(files)

@app.route('/api/images', methods=['POST'])
@login_required
def upload_email_image():
    """Upload an image to the email_images/ folder and return its public URL."""
    from werkzeug.utils import secure_filename
    file = request.files.get('file')
    if not file or file.filename == '':
        return jsonify({'error': 'No file provided'}), 400
    ext = file.filename.rsplit('.', 1)[-1].lower() if '.' in file.filename else ''
    if ext not in ALLOWED_IMAGE_EXTENSIONS:
        return jsonify({'error': f'File type .{ext} not allowed'}), 400
    filename = secure_filename(file.filename)
    # Avoid overwriting: append a counter if name already taken
    base, dot_ext = (filename.rsplit('.', 1)) if '.' in filename else (filename, '')
    dot_ext = ('.' + dot_ext) if dot_ext else ''
    counter = 1
    dest = os.path.join(EMAIL_IMAGES_DIR, filename)
    while os.path.exists(dest):
        filename = f"{base}_{counter}{dot_ext}"
        dest = os.path.join(EMAIL_IMAGES_DIR, filename)
        counter += 1
    file.save(dest)
    public_url = request.host_url.rstrip('/') + '/img/' + filename
    return jsonify({'filename': filename, 'url': public_url}), 201

@app.route('/api/images/<path:filename>', methods=['DELETE'])
@login_required
def delete_email_image(filename):
    """Delete an image from the email_images/ folder."""
    from werkzeug.utils import secure_filename
    safe = secure_filename(filename)
    dest = os.path.join(EMAIL_IMAGES_DIR, safe)
    if not os.path.exists(dest):
        return jsonify({'error': 'Not found'}), 404
    os.remove(dest)
    return jsonify({'success': True})

# ─────────────────────────────────────────────────────────────────────────────

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change password page."""
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')
        confirm_password = data.get('confirm_password', '')
        
        username = session.get('user')
        current_hash = hashlib.sha256(current_password.encode()).hexdigest()
        
        # Verify current password
        if AUTHORIZED_USERS.get(username) != current_hash:
            return jsonify({'success': False, 'error': 'Current password is incorrect'})
        
        # Validate new password
        if len(new_password) < 8:
            return jsonify({'success': False, 'error': 'Password must be at least 8 characters'})
        
        if new_password != confirm_password:
            return jsonify({'success': False, 'error': 'Passwords do not match'})
        
        # Update password
        new_hash = hashlib.sha256(new_password.encode()).hexdigest()
        AUTHORIZED_USERS[username] = new_hash
        
        _save_users_to_file()
        
        log_audit(AuditActions.CHANGE_PASSWORD, details=f"User '{username}' changed password")
        
        return jsonify({'success': True, 'message': 'Password changed successfully'})
    
    return render_template('change_password.html')
# ============================================

def _save_users_to_file():
    """Save users to a JSON file for persistence."""
    import json
    users_file = os.path.join(db_dir, 'users.json')
    data = {
        'users': {u: h for u, h in AUTHORIZED_USERS.items()},
        'admins': list(ADMIN_USERS)
    }
    with open(users_file, 'w') as f:
        json.dump(data, f, indent=2)

def _load_users_from_file():
    """Load users from JSON file."""
    import json
    users_file = os.path.join(db_dir, 'users.json')
    if os.path.exists(users_file):
        with open(users_file, 'r') as f:
            data = json.load(f)
            AUTHORIZED_USERS.update(data.get('users', {}))
            ADMIN_USERS.update(data.get('admins', []))

# Initialize SQLAlchemy (models) and ensure DB directory exists
if USE_CONFIG:
    db_dir = str(DATA_DIR)
else:
    db_dir = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(db_dir, exist_ok=True)

# Load saved users after db_dir is set
_load_users_from_file()

db_path = os.path.join(db_dir, 'campaigns.db')
app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI if 'SQLALCHEMY_DATABASE_URI' in globals() else f'sqlite:///{db_path}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
models_db.init_app(app)
with app.app_context():
    models_db.create_all()

# ============== BACKGROUND REMINDER SERVICE ==============
import threading

def reminder_service_worker():
    """Background worker that sends reminders for campaigns with reminders enabled."""
    import sendemails
    
    while True:
        try:
            time.sleep(60)  # Check every 60 seconds
            
            with app.app_context():
                from utils.models import Campaign, Result, SMTPProfile, LandingPage, Target
                
                # Find active campaigns with reminders enabled
                campaigns = Campaign.query.filter_by(reminders_enabled=True, status='running').all()
                
                for campaign in campaigns:
                    try:
                        # Get SMTP profile
                        smtp_profile = None
                        if campaign.smtp_profile_id:
                            smtp_profile = SMTPProfile.query.get(campaign.smtp_profile_id)
                        if not smtp_profile:
                            smtp_profile = SMTPProfile.query.filter_by(is_default=True).first()
                        
                        if not smtp_profile:
                            continue
                        
                        # Get landing page
                        landing_page = None
                        if campaign.landing_page_id:
                            landing_page = LandingPage.query.get(campaign.landing_page_id)
                        
                        # Get users who need reminders
                        results = Result.query.filter_by(campaign_id=campaign.id, clicked=True).all()
                        
                        reminder_interval = getattr(campaign, 'reminder_interval_minutes', 5) or 5
                        max_reminders = getattr(campaign, 'max_reminders', 12) or 12
                        
                        for result in results:
                            # Skip if questionnaire completed
                            if getattr(result, 'questionnaire_completed', False):
                                continue
                            
                            # Skip if max reminders reached
                            if (getattr(result, 'reminder_count', 0) or 0) >= max_reminders:
                                continue
                            
                            # Check if enough time has passed since last reminder
                            last_sent = getattr(result, 'last_reminder_sent', None)
                            if last_sent:
                                time_since_last = (datetime.now() - last_sent).total_seconds() / 60
                                if time_since_last < reminder_interval:
                                    continue
                            else:
                                # First reminder - check time since click
                                if result.clicked_at:
                                    time_since_click = (datetime.now() - result.clicked_at).total_seconds() / 60
                                    if time_since_click < reminder_interval:
                                        continue
                            
                            # Verify target exists and email looks valid before sending
                            try:
                                import re
                                target = get_target_for_result(result, campaign.id)
                                if not target:
                                    print(f"[Reminder Service] Skipping unknown email {result.email} for campaign {campaign.name}")
                                    continue
                                # Basic email format validation
                                if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', result.email or ''):
                                    print(f"[Reminder Service] Skipping invalid email {result.email} for campaign {campaign.name}")
                                    continue

                                # Send reminder
                                
                                # Build questionnaire link
                                base_url = TRACKING_BASE_URL or 'https://localhost:7443'
                                if landing_page:
                                    # Use token-based link for reliable tracking
                                    questionnaire_link = f"{base_url}/landing/{landing_page.id}/submit?token={result.token}"
                                else:
                                    questionnaire_link = "#"
                                
                                # Get email HTML
                                html_content = getattr(campaign, 'reminder_html', '') or ''
                                if not html_content:
                                    html_content = f"""
<html>
<body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
    <h2 style="color: #e94560;">Security Awareness Assessment Reminder</h2>
    <p>Please complete your security awareness assessment:</p>
    <p><a href="{questionnaire_link}">Click here to complete the assessment</a></p>
</body>
</html>
"""
                                else:
                                    # Find target for personalization
                                    target = get_target_for_result(result, campaign.id)
                                    first_name = target.first_name if target else 'Colleague'
                                    last_name = target.last_name if target else ''

                                    # Robust variable replacement
                                    replacements = {
                                        '{{questionnaire_link}}': questionnaire_link,
                                        '{{questionaire_link}}': questionnaire_link,  # Handle common typo
                                        '{{ questionnaire_link }}': questionnaire_link,
                                        '{{email}}': result.email,
                                        '{{campaign_name}}': campaign.name,
                                        '{{FirstName}}': first_name,
                                        '{{LastName}}': last_name,
                                    }
                                    
                                    for key, value in replacements.items():
                                        if value is not None:
                                            html_content = html_content.replace(key, str(value))
                                    
                                    # Also try to inject into empty hrefs if variable was missing
                                    if 'href=""' in html_content:
                                        html_content = html_content.replace('href=""', f'href="{questionnaire_link}"')
                                    if "href=''" in html_content:
                                        html_content = html_content.replace("href=''", f"href='{questionnaire_link}'")
                                
                                subject = getattr(campaign, 'reminder_subject', 'Reminder: Complete Your Security Assessment') or 'Reminder: Complete Your Security Assessment'
                                
                                # Use sendemails.send_email for unified sending and logging
                                sent = sendemails.send_email(
                                    to_email=result.email,
                                    subject=subject,
                                    html_content=html_content
                                )
                                if sent:
                                    # Update result
                                    result.last_reminder_sent = datetime.now()
                                    result.reminder_count = (getattr(result, 'reminder_count', 0) or 0) + 1
                                    models_db.session.commit()
                                    print(f"[Reminder Service] Sent reminder to {result.email} for campaign {campaign.name}")
                                else:
                                    print(f"[Reminder Service] Error sending reminder to {result.email}: see email_sender.log for details")
                            except Exception as e:
                                print(f"[Reminder Service] Error sending reminder to {result.email}: {e}")
                    
                    except Exception as e:
                        print(f"[Reminder Service] Error processing campaign {campaign.id}: {e}")
        
        except Exception as e:
            print(f"[Reminder Service] Error in reminder loop: {e}")

# Start the reminder service in background thread
reminder_thread = threading.Thread(target=reminder_service_worker, daemon=True)
reminder_thread.start()
print("[Reminder Service] Background reminder service started")
# ===========================================================

# Add context processor to make ADMIN_USERS available in all templates
@app.context_processor
def inject_admin_users():
    """Inject ADMIN_USERS into all templates."""
    return {'ADMIN_USERS': ADMIN_USERS}


@app.route('/')
@login_required
def dashboard():
    """Dashboard with real metrics from DB."""
    from utils.models import Campaign, Result, Target
    
    log_audit(AuditActions.VIEW_DASHBOARD)
    
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).limit(5).all()
    all_campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    total_campaigns = Campaign.query.count()
    active_campaigns = Campaign.query.filter_by(status='running').count()
    
    # Calculate aggregate metrics
    all_results = Result.query.all()
    total_sent = len(all_results)
    total_clicked = sum(1 for r in all_results if r.clicked)
    total_opened = sum(1 for r in all_results if r.opened)
    total_reported = sum(1 for r in all_results if getattr(r, 'reported', False))
    total_compromised = sum(1 for r in all_results if is_compromised(r))
    
    click_rate = round((total_clicked / total_sent * 100), 2) if total_sent > 0 else 0
    open_rate = round((total_opened / total_sent * 100), 2) if total_sent > 0 else 0
    
    # Build SBU stats
    sbu_stats = {}
    for result in all_results:
        target = get_target_for_result(result)
        sbu = target.sbu if target and target.sbu else 'Unknown'
        if sbu not in sbu_stats:
            sbu_stats[sbu] = {'targeted': 0, 'clicked': 0, 'reported': 0, 'compromised': 0, 'opened': 0}
        sbu_stats[sbu]['targeted'] += 1
        if result.clicked:
            sbu_stats[sbu]['clicked'] += 1
        if result.opened:
            sbu_stats[sbu]['opened'] += 1
        if getattr(result, 'reported', False):
            sbu_stats[sbu]['reported'] += 1
        if is_compromised(result):
            sbu_stats[sbu]['compromised'] += 1
    
    return render_template('dashboard_with_layout.html',
                         campaigns=campaigns,
                         all_campaigns=all_campaigns,
                         total_campaigns=total_campaigns,
                         active_campaigns=active_campaigns,
                         total_sent=total_sent,
                         total_clicked=total_clicked,
                         total_reported=total_reported,
                         total_compromised=total_compromised,
                         click_rate=click_rate,
                         open_rate=open_rate,
                         sbu_stats=sbu_stats)


# --------- Dashboard API endpoints ---------
@app.route('/api/dashboard/stats')
@login_required
def dashboard_stats_api():
    """API endpoint for dashboard stats, filterable by campaign."""
    from utils.models import Result, Target
    
    campaign_id = request.args.get('campaign_id', 'all')
    
    if campaign_id == 'all':
        results = Result.query.all()
    else:
        results = Result.query.filter_by(campaign_id=int(campaign_id)).all()
    
    total_targeted = len(results)
    total_clicked = sum(1 for r in results if r.clicked)
    total_opened = sum(1 for r in results if r.opened)
    total_reported = sum(1 for r in results if getattr(r, 'reported', False))
    total_compromised = sum(1 for r in results if is_compromised(r))
    
    click_rate = (total_clicked / total_targeted * 100) if total_targeted > 0 else 0
    open_rate = (total_opened / total_targeted * 100) if total_targeted > 0 else 0
    
    # Build SBU stats
    sbu_stats = {}
    for result in results:
        target = get_target_for_result(result)
        sbu = target.sbu if target and target.sbu else 'Unknown'
        if sbu not in sbu_stats:
            sbu_stats[sbu] = {'targeted': 0, 'clicked': 0, 'reported': 0, 'compromised': 0, 'opened': 0}
        sbu_stats[sbu]['targeted'] += 1
        if result.clicked:
            sbu_stats[sbu]['clicked'] += 1
        if result.opened:
            sbu_stats[sbu]['opened'] += 1
        if getattr(result, 'reported', False):
            sbu_stats[sbu]['reported'] += 1
        if is_compromised(result):
            sbu_stats[sbu]['compromised'] += 1
    
    return jsonify({
        'total_targeted': total_targeted,
        'total_clicked': total_clicked,
        'total_opened': total_opened,
        'total_reported': total_reported,
        'total_compromised': total_compromised,
        'click_rate': click_rate,
        'open_rate': open_rate,
        'sbu_stats': sbu_stats
    })


@app.route('/api/dashboard/drilldown')
@login_required
def dashboard_drilldown_api():
    """API endpoint for drilling down to individual targets in an SBU."""
    from utils.models import Result, Target
    
    campaign_id = request.args.get('campaign_id', 'all')
    sbu = request.args.get('sbu', '')
    
    if campaign_id == 'all':
        results = Result.query.all()
    else:
        results = Result.query.filter_by(campaign_id=int(campaign_id)).all()
    
    targets = []
    for result in results:
        target = get_target_for_result(result)
        target_sbu = target.sbu if target and target.sbu else 'Unknown'
        
        if target_sbu == sbu or (not sbu and target_sbu == 'Unknown'):
            targets.append({
                'id': result.id,
                'email': result.email,
                'first_name': target.first_name if target else '',
                'last_name': target.last_name if target else '',
                'opened': result.opened,
                'clicked': result.clicked,
                'reported': getattr(result, 'reported', False),
                'compromised': is_compromised(result),
                'clicked_at': result.clicked_at.strftime('%Y-%m-%d %H:%M') if result.clicked_at else None
            })
    
    return jsonify({'targets': targets})


@app.route('/api/dashboard/update_result', methods=['POST'])
@login_required
def update_result_api():
    """API endpoint to update reported/compromised status for a result."""
    from utils.models import Result, db
    
    data = request.get_json()
    result_id = data.get('result_id')
    field = data.get('field')
    value = data.get('value')
    
    if field not in ['reported', 'compromised']:
        return jsonify({'success': False, 'error': 'Invalid field'})
    
    result = Result.query.get(result_id)
    if not result:
        return jsonify({'success': False, 'error': 'Result not found'})
    
    setattr(result, field, bool(value))
    if field == 'reported' and bool(value):
        result.opened = True
        if not result.opened_at:
            result.opened_at = datetime.now()
    db.session.commit()
    log_metric(field, result.campaign_id, result.email, result.token, {'value': bool(value)})
    
    log_audit(AuditActions.UPDATE_RESULT, details=f"Set {field}={value} for result {result_id} (email: {result.email})")
    
    return jsonify({'success': True})


@app.route('/api/dashboard/export')
@login_required
def dashboard_export_api():
    """Export dashboard data as CSV."""
    from utils.models import Result, Target
    import csv
    from io import StringIO
    from flask import Response
    
    campaign_id = request.args.get('campaign_id', 'all')
    sbu_filter = request.args.get('sbu', '')
    
    log_audit(AuditActions.EXPORT_DATA, details=f"Exported data for campaign={campaign_id}, sbu_filter={sbu_filter or 'all'}")
    
    if campaign_id == 'all':
        results = Result.query.all()
    else:
        results = Result.query.filter_by(campaign_id=int(campaign_id)).all()
    
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['SBU', 'First Name', 'Last Name', 'Email', 'Opened', 'Clicked', 'Reported', 'Compromised', 'Clicked At'])
    
    for result in results:
        target = get_target_for_result(result)
        target_sbu = target.sbu if target and target.sbu else 'Unknown'
        
        if sbu_filter and target_sbu != sbu_filter:
            continue
        
        writer.writerow([
            target_sbu,
            target.first_name if target else '',
            target.last_name if target else '',
            result.email,
            'Yes' if result.opened else 'No',
            'Yes' if result.clicked else 'No',
            'Yes' if getattr(result, 'reported', False) else 'No',
            'Yes' if is_compromised(result) else 'No',
            result.clicked_at.strftime('%Y-%m-%d %H:%M') if result.clicked_at else ''
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=phishing_report_{campaign_id}.csv'}
    )


@app.route('/api/dashboard/export_sbu')
@login_required
def dashboard_export_sbu_api():
    """Export SBU statistics as CSV."""
    from utils.models import Result, Target, Campaign
    import csv
    from io import StringIO
    from flask import Response
    
    campaign_id = request.args.get('campaign_id', 'all')
    
    log_audit(AuditActions.EXPORT_DATA, details=f"Exported SBU statistics for campaign={campaign_id}")
    
    if campaign_id == 'all':
        results = Result.query.all()
        campaign_name = 'All Campaigns'
    else:
        results = Result.query.filter_by(campaign_id=int(campaign_id)).all()
        campaign = Campaign.query.get(int(campaign_id))
        campaign_name = campaign.name if campaign else f'Campaign {campaign_id}'
    
    # Build SBU stats
    sbu_stats = {}
    for result in results:
        target = get_target_for_result(result)
        sbu = target.sbu if target and target.sbu else 'Unknown'
        if sbu not in sbu_stats:
            sbu_stats[sbu] = {'targeted': 0, 'clicked': 0, 'reported': 0, 'compromised': 0, 'opened': 0}
        sbu_stats[sbu]['targeted'] += 1
        if result.clicked:
            sbu_stats[sbu]['clicked'] += 1
        if result.opened:
            sbu_stats[sbu]['opened'] += 1
        if getattr(result, 'reported', False):
            sbu_stats[sbu]['reported'] += 1
        if is_compromised(result):
            sbu_stats[sbu]['compromised'] += 1
    
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['SBU', 'Targeted', 'Opened', 'Open Rate %', 'Clicked', 'Click Rate %', 'Reported', 'Compromised'])
    
    for sbu, stats in sorted(sbu_stats.items()):
        open_rate = round((stats['opened'] / stats['targeted'] * 100), 2) if stats['targeted'] > 0 else 0
        click_rate = round((stats['clicked'] / stats['targeted'] * 100), 2) if stats['targeted'] > 0 else 0
        
        writer.writerow([
            sbu,
            stats['targeted'],
            stats['opened'],
            open_rate,
            stats['clicked'],
            click_rate,
            stats['reported'],
            stats['compromised']
        ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename=sbu_statistics_{campaign_id}.csv'}
    )


@app.route('/api/export/campaign_xlsx')
@login_required
def export_campaign_xlsx():
    """Export a full campaign report as a formatted multi-sheet .xlsx file."""
    from utils.models import Campaign, Result, Target
    from utils.excel_export import build_campaign_xlsx
    from flask import send_file

    campaign_id = request.args.get('campaign_id', 'all')

    # ── gather campaign object ─────────────────────────────────────────────
    if campaign_id == 'all':
        # Aggregate across all campaigns — use a synthetic object
        from types import SimpleNamespace
        campaign = SimpleNamespace(
            id=None,
            name="All Campaigns",
            description="Aggregated data across all phishing campaigns.",
            campaign_type=None,
            subject=None,
            status="completed",
            created_at=None,
            started_at=None,
            finished_at=None,
            landing_page_id=None,
        )
        results = Result.query.all()
        filename = "phishing_report_all_campaigns"
    else:
        campaign = Campaign.query.get_or_404(int(campaign_id))
        results = Result.query.filter_by(campaign_id=campaign.id).all()
        safe_name = campaign.name.replace(" ", "_").replace("/", "-")
        filename = f"phishing_report_{safe_name}"

    log_audit(AuditActions.EXPORT_DATA,
              details=f"Excel export for campaign={campaign_id}")

    # ── build stats dict (same logic as campaign_report_page) ─────────────
    # compromised = clicked the link but never reported (derived, not DB flag) — uses module-level is_compromised()
    total                  = len(results)
    clicked                = sum(1 for r in results if r.clicked)
    opened                 = sum(1 for r in results if r.opened)
    reported               = sum(1 for r in results if getattr(r, 'reported', False))
    compromised            = sum(1 for r in results if is_compromised(r))
    questionnaire_finished = sum(1 for r in results if getattr(r, 'questionnaire_completed', False))

    click_rate           = round(clicked                / total * 100, 2) if total > 0 else 0.0
    open_rate            = round(opened                 / total * 100, 2) if total > 0 else 0.0
    report_rate          = round(reported               / total * 100, 2) if total > 0 else 0.0
    compromise_rate      = round(compromised            / total * 100, 2) if total > 0 else 0.0
    questionnaire_rate   = round(questionnaire_finished / total * 100, 2) if total > 0 else 0.0

    sbu_stats = {}
    for r in results:
        t = get_target_for_result(r, int(campaign_id) if campaign_id != 'all' else None)
        sbu = (t.sbu if t and t.sbu else 'Unknown').strip()
        if sbu not in sbu_stats:
            sbu_stats[sbu] = {'targeted': 0, 'clicked': 0, 'opened': 0,
                              'reported': 0, 'compromised': 0}
        sbu_stats[sbu]['targeted']    += 1
        if r.clicked:                     sbu_stats[sbu]['clicked']    += 1
        if r.opened:                      sbu_stats[sbu]['opened']     += 1
        if getattr(r, 'reported', False): sbu_stats[sbu]['reported']   += 1
        if is_compromised(r):            sbu_stats[sbu]['compromised'] += 1

    sbu_list = []
    for name, data in sorted(sbu_stats.items()):
        tt = data['targeted']
        sbu_list.append({
            'sbu':              name,
            'targeted':         tt,
            'opened':           data['opened'],
            'clicked':          data['clicked'],
            'reported':         data['reported'],
            'compromised':      data['compromised'],
            'open_rate':        round(data['opened']      / tt * 100, 2) if tt > 0 else 0,
            'click_rate':       round(data['clicked']     / tt * 100, 2) if tt > 0 else 0,
            'report_rate':      round(data['reported']    / tt * 100, 2) if tt > 0 else 0,
            'compromise_rate':  round(data['compromised'] / tt * 100, 2) if tt > 0 else 0,
        })
    sbu_list.sort(key=lambda x: x['click_rate'], reverse=True)

    stats = {
        'total': total, 'opened': opened, 'clicked': clicked,
        'reported': reported, 'compromised': compromised,
        'questionnaire_finished': questionnaire_finished,
        'open_rate': open_rate, 'click_rate': click_rate,
        'report_rate': report_rate, 'compromise_rate': compromise_rate,
        'questionnaire_rate': questionnaire_rate,
        'sbu_list': sbu_list,
    }

    # ── build per-target rows ──────────────────────────────────────────────
    results_data = []
    for r in results:
        t = get_target_for_result(r, int(campaign_id) if campaign_id != 'all' else None)
        results_data.append({
            'email':       r.email,
            'first_name':  t.first_name if t else '',
            'last_name':   t.last_name  if t else '',
            'sbu':         t.sbu        if t and t.sbu else '',
            'position':    t.position   if t and hasattr(t, 'position') else '',
            'opened':      bool(r.opened),
            'clicked':     bool(r.clicked),
            'submitted':   bool(getattr(r, 'submitted', False)),
            'reported':       bool(getattr(r, 'reported', False)),
            'compromised':    is_compromised(r),
            'reminder_count': int(getattr(r, 'reminder_count', 0) or 0),
            'clicked_at':  r.clicked_at.strftime('%Y-%m-%d %H:%M') if r.clicked_at else '',
        })

    # ── fetch campaign email HTML and landing page HTML for preview sheets ──
    email_html = None
    if hasattr(campaign, 'template_id') and campaign.template_id:
        from utils.models import EmailTemplate
        tmpl = EmailTemplate.query.get(campaign.template_id)
        if tmpl:
            email_html = tmpl.html_content

    landing_page_html = None
    if hasattr(campaign, 'landing_page_id') and campaign.landing_page_id:
        from utils.models import LandingPage
        lp = LandingPage.query.get(campaign.landing_page_id)
        if lp and lp.html_content:
            landing_page_html = lp.html_content

    xlsx_buf = build_campaign_xlsx(campaign, stats, results_data,
                                   email_html=email_html,
                                   landing_page_html=landing_page_html)

    return send_file(
        xlsx_buf,
        mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        as_attachment=True,
        download_name=f"{filename}.xlsx",
    )



@app.route('/templates/editor', methods=['GET', 'POST'])
@app.route('/template_editor', methods=['GET', 'POST'])
@login_required
def template_editor():
    """Template editor page."""
    import sendemails
    from utils.models import EmailTemplate, db
    
    if request.method == 'POST':
        data = request.get_json() if request.is_json else request.form
        subject = data.get('subject')
        html_content = data.get('html_content')
        template_id = data.get('id')
        name = data.get('name', subject or 'Untitled Template')
        
        if template_id:
            template = EmailTemplate.query.get(template_id)
            if template:
                template.subject = subject
                template.html_content = html_content
                template.name = name
            else:
                return jsonify({"success": False, "message": "Template not found"}), 404
        else:
            template = EmailTemplate(name=name, subject=subject, html_content=html_content)
            db.session.add(template)
        
        db.session.commit()
        return jsonify({"success": True, "message": "Template saved successfully", "id": template.id})
    
    # GET request
    template_id = request.args.get('id')
    if template_id:
        template = EmailTemplate.query.get(template_id)
        if template:
            return render_template('template_editor.html',
                                 subject=template.subject,
                                 html_content=template.html_content,
                                 template_id=template.id,
                                 template_name=template.name)
    
    # Load default template
    default_html = sendemails.create_email_content(
        first_name="John",
        link="http://example.com/track?token=demo",
        pixel_url="http://example.com/pixel?token=demo"
    )
    
    return render_template('template_editor.html',
                         subject=sendemails.EMAIL_SUBJECT,
                         html_content=default_html)


@app.route('/templates/list', methods=['GET'])
@login_required
def list_templates():
    from utils.models import EmailTemplate
    templates = EmailTemplate.query.order_by(EmailTemplate.updated_at.desc()).all()
    return jsonify([{
        'id': t.id,
        'name': t.name,
        'subject': t.subject,
        'html_content': t.html_content,
        'tags': getattr(t, 'tags', ''),
        'updated_at': t.updated_at.isoformat() if t.updated_at else None
    } for t in templates])


@app.route('/templates/save', methods=['POST'])
@login_required
def save_template():
    """Save or update a template."""
    from utils.models import EmailTemplate, TemplateImage, db
    
    data = request.get_json()
    template_id = data.get('template_id') or data.get('id')
    name = data.get('name', 'Untitled Template')
    subject = data.get('subject', '')
    html_content = data.get('html_content', '')
    tags = data.get('tags', '')
    sender_name = data.get('sender_name', '')
    sender_email = data.get('sender_email', '')
    
    try:
        if template_id:
            template = EmailTemplate.query.get(template_id)
            if not template:
                return jsonify({'success': False, 'error': 'Template not found'}), 404
            template.name = name
            template.subject = subject
            template.html_content = html_content
            if hasattr(template, 'tags'):
                template.tags = tags
            if hasattr(template, 'sender_name'):
                template.sender_name = sender_name
            if hasattr(template, 'sender_email'):
                template.sender_email = sender_email
        else:
            template = EmailTemplate(name=name, subject=subject, html_content=html_content)
            if hasattr(EmailTemplate, 'tags'):
                template.tags = tags
            if hasattr(EmailTemplate, 'sender_name'):
                template.sender_name = sender_name
            if hasattr(EmailTemplate, 'sender_email'):
                template.sender_email = sender_email
            db.session.add(template)
        
        db.session.commit()
        log_audit(AuditActions.EDIT_TEMPLATE, details=f"Saved template: {name}")
        
        return jsonify({
            'success': True,
            'id': template.id,
            'images': [{
                'id': img.id,
                'cid': img.cid,
                'filename': img.filename,
                'mime_type': img.mime_type,
                'preview': f'/templates/{template.id}/images/{img.id}/preview',
            } for img in TemplateImage.query.filter_by(template_id=template.id).all()]
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/templates/delete/<int:template_id>', methods=['POST', 'DELETE'])
@login_required
def delete_template(template_id):
    """Delete a template."""
    from utils.models import EmailTemplate, db
    
    try:
        template = EmailTemplate.query.get(template_id)
        if not template:
            return jsonify({'success': False, 'error': 'Template not found'}), 404
        
        name = template.name
        db.session.delete(template)
        db.session.commit()
        
        log_audit(AuditActions.DELETE_TEMPLATE, details=f"Deleted template: {name}")
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/templates/get/<int:template_id>', methods=['GET'])
@login_required
def get_template(template_id):
    from utils.models import EmailTemplate
    template = EmailTemplate.query.get(template_id)
    if not template:
        return jsonify({'success': False, 'error': 'Template not found'}), 404
    
    return jsonify({
        'success': True,
        'id': template.id,
        'name': template.name,
        'subject': template.subject,
        'html_content': template.html_content,
        'tags': getattr(template, 'tags', ''),
        'sender_name': getattr(template, 'sender_name', ''),
        'sender_email': getattr(template, 'sender_email', ''),
        'images': [{
            'id': img.id,
            'cid': img.cid,
            'filename': img.filename,
            'mime_type': img.mime_type,
            'preview': f'/templates/{template.id}/images/{img.id}/preview',
        } for img in getattr(template, 'images', [])]
    })


@app.route('/templates/send_test', methods=['POST'])
@login_required
def send_test_email():
    """Send a test email with the template, embedding CID images."""
    try:
        data = request.get_json(silent=True) or {}
        # Accept both JSON and form data
        email = data.get('to_email') or request.form.get('email')
        subject = data.get('subject') or request.form.get('subject')
        html_content = data.get('html_content') or request.form.get('html_content')
        smtp_profile_id = data.get('smtp_profile_id') or request.form.get('smtp_profile_id')
        template_id = data.get('template_id') or request.form.get('template_id')

        if not email or not html_content:
            return jsonify({'success': False, 'error': 'Missing required fields'})

        subject = subject or 'Test Email'

        try:
            from config import TRACKING_BASE_URL
            base_url = TRACKING_BASE_URL
        except ImportError:
            base_url = 'https://localhost:7443'

        # Replace template variables with test data.
        # Handle both {{var}} and {{ var }} (with/without spaces), and common name variants.
        import re as _re
        test_content = html_content
        pixel_url = f"{base_url}/pixel?token=TEST-TOKEN"
        pixel_img = f'<img src="{pixel_url}" width="1" height="1" style="border:0;margin:0;padding:0;" alt="" />'
        phishing_link_url = f'{base_url}/test-link'

        replacements = {
            # phishing link — all variants
            'phishing_link': phishing_link_url,
            'PhishingLink': phishing_link_url,
            'link': phishing_link_url,
            'Link': phishing_link_url,
            # tracking pixel
            'tracking_pixel': pixel_img,
            'TrackingPixel': pixel_img,
            # name variants
            'first_name': 'Test',
            'FirstName': 'Test',
            'firstname': 'Test',
            'last_name': 'User',
            'LastName': 'User',
            'lastname': 'User',
            'full_name': 'Test User',
            'FullName': 'Test User',
            'name': 'Test User',
            'Name': 'Test User',
            # email
            'email': email,
            'Email': email,
            # date
            'date': datetime.now().strftime('%B %d, %Y'),
            'Date': datetime.now().strftime('%B %d, %Y'),
        }
        for var, val in replacements.items():
            # match {{ var }} with optional surrounding spaces
            test_content = _re.sub(r'\{\{\s*' + _re.escape(var) + r'\s*\}\}', val, test_content)

        # ── Build the email message with CID image support ────────────────
        import smtplib, re
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        from email.mime.image import MIMEImage
        from utils.models import SMTPProfile, TemplateImage

        # Determine SMTP settings
        smtp_server = None; smtp_port = 25; smtp_user = ''; smtp_password = ''
        sender_display = 'PhishSim Test'; sender_email_addr = ''
        use_tls = False; use_ssl = False; reply_to = None; custom_headers = {}

        profile = None
        if smtp_profile_id:
            profile = SMTPProfile.query.get(int(smtp_profile_id))
        if not profile:
            profile = SMTPProfile.query.filter_by(is_default=True).first()

        if profile:
            smtp_server = profile.smtp_server
            smtp_port = profile.smtp_port
            smtp_user = profile.smtp_user or ''
            smtp_password = profile.smtp_password or ''
            sender_display = profile.from_name or profile.sender_name or sender_display
            sender_email_addr = profile.sender_email or smtp_user
            use_tls = profile.use_tls
            use_ssl = profile.use_ssl
            reply_to = profile.reply_to
            if profile.custom_headers:
                try:
                    import json as _json
                    custom_headers = _json.loads(profile.custom_headers) if isinstance(profile.custom_headers, str) else profile.custom_headers
                except Exception:
                    custom_headers = {}
        else:
            # fallback to sendemails defaults
            try:
                import sendemails as _se
                smtp_server = getattr(_se, 'SMTP_SERVER', 'localhost')
                smtp_port = getattr(_se, 'SMTP_PORT', 25)
                smtp_user = getattr(_se, 'SMTP_USER', '')
                smtp_password = getattr(_se, 'SMTP_PASSWORD', '')
                sender_display = getattr(_se, 'SENDER_DISPLAY_NAME', 'PhishSim')
                sender_email_addr = smtp_user
            except Exception:
                smtp_server = 'localhost'

        msg = MIMEMultipart('related')
        msg['Subject'] = f"[TEST] {subject}"
        # Let the template's sender_name/sender_email fields override the SMTP profile defaults
        override_name = data.get('sender_name', '').strip()
        override_email = data.get('sender_email', '').strip()
        final_display = override_name or sender_display
        final_from = override_email or sender_email_addr
        msg['From'] = f"{final_display} <{final_from}>" if final_from else final_display
        msg['To'] = email
        if reply_to:
            msg['Reply-To'] = reply_to
        for hdr, val in custom_headers.items():
            msg[hdr] = val

        # Mirror the production sender structure so CID rendering is consistent in clients.
        alt = MIMEMultipart('alternative')
        # Normalize cid:<name> -> cid:name to match attached Content-ID headers.
        import re as _re
        test_content = _re.sub(r'cid:\s*<([^>]+)>', r'cid:\1', test_content, flags=_re.IGNORECASE)
        alt.attach(MIMEText(test_content, 'html'))
        msg.attach(alt)

        # Attach CID images and file attachments from the database for the chosen template
        if template_id:
            try:
                from utils.models import EmailTemplate, TemplateAttachment, get_effective_template_images
                from email.mime.base import MIMEBase
                from email import encoders as _encoders
                template_obj = EmailTemplate.query.get(int(template_id))
                db_images = get_effective_template_images(template_obj)
                for img in db_images:
                    mime_subtype = img.mime_type.split('/')[-1].lower()
                    if mime_subtype == 'jpg':
                        mime_subtype = 'jpeg'
                    part = MIMEImage(bytes(img.data), mime_subtype)
                    part.add_header('Content-ID', f'<{img.cid}>')
                    part.add_header('Content-Disposition', 'inline', filename=img.filename)
                    part.set_param('name', img.filename)
                    msg.attach(part)
                db_atts = TemplateAttachment.query.filter_by(template_id=int(template_id)).all()
                for att in db_atts:
                    main_t, sub_t = att.mime_type.split('/', 1) if '/' in att.mime_type else ('application', 'octet-stream')
                    part = MIMEBase(main_t, sub_t)
                    part.set_payload(bytes(att.data))
                    _encoders.encode_base64(part)
                    part.add_header('Content-Disposition', 'attachment', filename=att.filename)
                    msg.attach(part)
                app.logger.info(f"Test email: attached {len(db_images)} CID images + {len(db_atts)} files (template {template_id})")
            except Exception as e:
                app.logger.warning(f"Could not attach files: {e}")

        # Send
        if use_ssl and smtp_port == 465:
            import ssl as _ssl
            ctx = _ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_server, smtp_port, context=ctx) as srv:
                if smtp_user and smtp_password:
                    srv.login(smtp_user, smtp_password)
                srv.send_message(msg)
        else:
            with smtplib.SMTP(smtp_server, smtp_port) as srv:
                if use_tls:
                    srv.starttls()
                if smtp_user and smtp_password:
                    srv.login(smtp_user, smtp_password)
                srv.send_message(msg)

        return jsonify({'success': True, 'message': f'Test email sent to {email}'})

    except Exception as e:
        app.logger.error(f"Test email error: {e}")
        return jsonify({'success': False, 'error': str(e)})



@app.route('/targets')
@login_required
def targets_page():
    """Targets management page - only shows manually added targets from example.com domain."""
    from utils.models import Target
    
    # Get all targets without a campaign_id (manually added)
    all_targets = Target.query.filter_by(campaign_id=None).order_by(Target.id.desc()).all()
    
    # Only show targets from example.com domain
    targets = [t for t in all_targets if t.email.lower().endswith('@example.com')]
    
    return render_template('targets_page.html', targets=targets)


@app.route('/targets/list', methods=['GET'])
@login_required
def list_targets_json():
    """Get all manually added targets from example.com domain as JSON."""
    from utils.models import Target
    
    # Get all targets without a campaign_id (manually added)
    all_targets = Target.query.filter_by(campaign_id=None).order_by(Target.id.desc()).all()
    
    # Only return targets from example.com domain
    targets = [t for t in all_targets if t.email.lower().endswith('@example.com')]
    
    return jsonify([{
        'id': t.id,
        'first_name': t.first_name,
        'last_name': t.last_name,
        'email': t.email,
        'sbu': t.sbu,
        'position': t.position,
        'past_target': t.past_target
    } for t in targets])


@app.route('/targets/add', methods=['POST'])
@login_required
def add_target():
    """Add a single target."""
    from utils.models import Target, db
    data = request.get_json()
    
    target = Target(
        first_name=data.get('first_name'),
        last_name=data.get('last_name'),
        email=data.get('email')
    )
    db.session.add(target)
    db.session.commit()
    
    log_audit(AuditActions.ADD_TARGET, details=f"Added target: {data.get('email')}")
    
    return jsonify({'success': True, 'id': target.id})


@app.route('/targets/bulk_add', methods=['POST'])
@login_required
def bulk_add_targets():
    """Bulk import targets from CSV/XLSX."""
    from utils.models import Target, db
    data = request.get_json()
    targets_data = data.get('targets', [])
    
    added = 0
    for t_data in targets_data:
        target = Target(
            first_name=t_data.get('first_name'),
            last_name=t_data.get('last_name'),
            email=t_data.get('email'),
            sbu=t_data.get('sbu'),
            position=t_data.get('position')
        )
        db.session.add(target)
        added += 1
    
    db.session.commit()
    log_audit(AuditActions.BULK_ADD_TARGETS, details=f"Bulk added {added} targets")
    return jsonify({'success': True, 'added': added})


@app.route('/targets/edit/<int:target_id>', methods=['POST'])
@login_required
def edit_target(target_id):
    """Edit a target."""
    from utils.models import Target, db
    data = request.get_json()
    
    target = Target.query.get(target_id)
    if not target:
        return jsonify({'success': False, 'error': 'Target not found'}), 404
    
    target.first_name = data.get('first_name')
    target.last_name = data.get('last_name')
    target.email = data.get('email')
    db.session.commit()
    
    return jsonify({'success': True})


@app.route('/targets/delete/<int:target_id>', methods=['POST'])
@login_required
def delete_target(target_id):
    """Delete a target."""
    from utils.models import Target, db
    
    target = Target.query.get(target_id)
    if not target:
        return jsonify({'success': False, 'error': 'Target not found'}), 404
    
    email = target.email
    db.session.delete(target)
    db.session.commit()
    
    log_audit(AuditActions.DELETE_TARGET, details=f"Deleted target: {email}")
    
    return jsonify({'success': True})


@app.route('/targets/bulk_delete', methods=['POST'])
@login_required
def bulk_delete_targets():
    """Bulk delete targets."""
    from utils.models import Target, db
    data = request.get_json()
    ids = data.get('ids', [])
    
    Target.query.filter(Target.id.in_(ids)).delete(synchronize_session=False)
    db.session.commit()
    
    log_audit(AuditActions.BULK_DELETE_TARGETS, details=f"Bulk deleted {len(ids)} targets")
    
    return jsonify({'success': True, 'deleted': len(ids)})


@app.route('/targets/tag_past_targets', methods=['POST'])
@login_required
def tag_past_targets():
    """Tag targets from past campaigns based on email list."""
    from utils.models import Target, db
    data = request.get_json()
    emails = data.get('emails', [])
    
    if not emails:
        return jsonify({'success': False, 'error': 'No emails provided'}), 400
    
    # Find all targets with matching emails and tag them
    targets = Target.query.filter(Target.email.in_(emails)).all()
    tagged = 0
    
    for target in targets:
        if not target.past_target:
            target.past_target = True
            tagged += 1
    
    db.session.commit()
    
    return jsonify({'success': True, 'tagged': tagged, 'total': len(emails)})


# ============== AUDIT LOG VIEWER ==============
@app.route('/audit')
@login_required
def audit_logs_page():
    """Audit log viewer page."""
    return render_template('audit_logs.html')


@app.route('/api/audit/logs')
@login_required
def get_audit_logs_api():
    """API endpoint to get audit logs."""
    limit = request.args.get('limit', 100, type=int)
    user_filter = request.args.get('user', None)
    action_filter = request.args.get('action', None)
    
    logs = get_audit_logs(limit=limit, user_filter=user_filter, action_filter=action_filter)
    
    return jsonify({'logs': logs})


@app.route('/users')
@admin_required
def users_page():
    """User management page (admin only)."""
    users = [{'username': u, 'is_admin': u in ADMIN_USERS} for u in AUTHORIZED_USERS.keys()]
    return render_template('users_page.html', users=users, current_user=session.get('user'))

@app.route('/api/users/add', methods=['POST'])
@admin_required
def add_user():
    """Add a new user (admin only)."""
    data = request.get_json()
    username = data.get('username', '').strip().lower()
    password = data.get('password', '')
    is_admin = data.get('is_admin', False)
    
    if not username or not password:
        return jsonify({'success': False, 'error': 'Username and password required'})
    
    if username in AUTHORIZED_USERS:
        return jsonify({'success': False, 'error': 'User already exists'})
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    AUTHORIZED_USERS[username] = password_hash
    
    if is_admin:
        ADMIN_USERS.add(username)
    
    # Save to file for persistence
    _save_users_to_file()
    
    log_audit(AuditActions.ADD_USER, details=f"Added user: {username} (admin={is_admin})")
    
    return jsonify({'success': True})

@app.route('/api/users/delete/<username>', methods=['POST'])
@admin_required
def delete_user(username):
    """Delete a user (admin only)."""
    if username not in AUTHORIZED_USERS:
        return jsonify({'success': False, 'error': 'User not found'})
    
    if username == session.get('user'):
        return jsonify({'success': False, 'error': 'Cannot delete yourself'})
    
    del AUTHORIZED_USERS[username]
    ADMIN_USERS.discard(username)
    
    _save_users_to_file()
    
    log_audit(AuditActions.DELETE_USER, details=f"Deleted user: {username}")
    
    return jsonify({'success': True})


# ============== HISTORICAL DATA MANAGEMENT ==============
@app.route('/historical_data')
@login_required
def historical_data_page():
    """Historical campaign data management page."""
    from utils.models import Campaign
    
    # Get default SBUs from config
    try:
        from config import DEFAULT_SBUS
        default_sbus = DEFAULT_SBUS
    except ImportError:
        # Fallback if config doesn't have it
        default_sbus = [
            "Operations", "Sales", "IT", "HQ",
            "Insurance", "IT & MIS", "Marketing", "Finance",
            "HR", "Engineering"
        ]
    
    # Get all campaigns
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    
    return render_template('historical_data.html', 
                         campaigns=campaigns, 
                         default_sbus=default_sbus)


@app.route('/api/historical_data/add', methods=['POST'])
@login_required
def add_historical_data():
    """Add or update historical campaign data via web interface."""
    from utils.models import Campaign, Target, Result, db
    
    data = request.get_json()
    campaign_name = data.get('campaign_name', '').strip()
    campaign_date = data.get('campaign_date', '')  # Month/Year
    sbu_data = data.get('sbu_data', [])  # List of {sbu, targeted, clicked, reported}
    
    if not campaign_name:
        return jsonify({'success': False, 'error': 'Campaign name is required'})
    
    if not sbu_data:
        return jsonify({'success': False, 'error': 'At least one SBU entry is required'})
    
    try:
        # Check if campaign exists
        campaign = Campaign.query.filter_by(name=campaign_name).first()
        
        if campaign:
            # Update existing campaign - delete old results and targets
            Result.query.filter_by(campaign_id=campaign.id).delete()
            log_audit(AuditActions.EDIT_CAMPAIGN, details=f"Updated historical data for '{campaign_name}'")
        else:
            # Create new campaign
            campaign = Campaign(
                name=campaign_name,
                description=f"Historical campaign data from {campaign_date}" if campaign_date else "Historical campaign data",
                subject="Historical Campaign",
                template_html="<p>Historical campaign data</p>",
                status="completed",
                sender_name="PhishSim",
                sender_email="noreply@example.com",
                created_at=datetime.now(),
                started_at=datetime.now(),
                finished_at=datetime.now()
            )
            db.session.add(campaign)
            db.session.flush()
            log_audit(AuditActions.CREATE_CAMPAIGN, details=f"Created historical campaign '{campaign_name}'")
        
        # Process SBU data
        total_targeted = 0
        total_clicked = 0
        total_reported = 0
        
        for sbu_entry in sbu_data:
            sbu = sbu_entry.get('sbu', '').strip()
            if not sbu:
                continue
            
            try:
                targeted = int(sbu_entry.get('targeted', 0))
                clicked = int(sbu_entry.get('clicked', 0))
                reported = int(sbu_entry.get('reported', 0))
            except ValueError:
                continue
            
            # Create targets and results
            for i in range(targeted):
                email = f"{sbu.lower().replace(' ', '_').replace('&', 'and')}_user{i+1}@company.com"
                
                # Check if target exists
                target = Target.query.filter_by(email=email).first()
                if not target:
                    target = Target(
                        email=email,
                        first_name=f"User{i+1}",
                        last_name=sbu,
                        sbu=sbu,
                        position="Employee",
                        past_target=True
                    )
                    db.session.add(target)
                
                # Create result
                is_clicked = (i < clicked)
                is_reported = (i < reported)
                
                result = Result(
                    campaign_id=campaign.id,
                    email=email,
                    clicked=is_clicked,
                    reported=is_reported,
                    opened=True,
                    clicked_at=datetime.now() if is_clicked else None,
                    opened_at=datetime.now()
                )
                db.session.add(result)
                
                total_targeted += 1
                if is_clicked:
                    total_clicked += 1
                if is_reported:
                    total_reported += 1
        
        # Update campaign counts
        campaign.sent_count = total_targeted
        campaign.clicked_count = total_clicked
        
        db.session.commit()
        
        click_rate = (total_clicked / total_targeted * 100) if total_targeted > 0 else 0
        report_rate = (total_reported / total_targeted * 100) if total_targeted > 0 else 0
        
        return jsonify({
            'success': True,
            'campaign_id': campaign.id,
            'stats': {
                'targeted': total_targeted,
                'clicked': total_clicked,
                'reported': total_reported,
                'click_rate': round(click_rate, 2),
                'report_rate': round(report_rate, 2)
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/historical_data/update/<int:campaign_id>', methods=['POST'])
@login_required
def update_historical_data(campaign_id):
    """Update existing historical campaign data by ID."""
    from utils.models import Campaign, Target, Result, db
    
    data = request.get_json()
    campaign_name = data.get('campaign_name', '').strip()
    campaign_date = data.get('campaign_date', '')
    sbu_data = data.get('sbu_data', [])
    
    if not campaign_name:
        return jsonify({'success': False, 'error': 'Campaign name is required'})
    
    if not sbu_data:
        return jsonify({'success': False, 'error': 'At least one SBU entry is required'})
    
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'success': False, 'error': 'Campaign not found'})
        
        # Delete old results for this campaign
        Result.query.filter_by(campaign_id=campaign.id).delete()
        
        # Update campaign name if changed
        campaign.name = campaign_name
        if campaign_date:
            campaign.description = f"Historical campaign data from {campaign_date}"
        
        # Process SBU data
        total_targeted = 0
        total_clicked = 0
        total_reported = 0
        
        for sbu_entry in sbu_data:
            sbu = sbu_entry.get('sbu', '').strip()
            if not sbu:
                continue
            
            try:
                targeted = int(sbu_entry.get('targeted', 0))
                clicked = int(sbu_entry.get('clicked', 0))
                reported = int(sbu_entry.get('reported', 0))
            except ValueError:
                continue
            
            # Create targets and results
            for i in range(targeted):
                email = f"{sbu.lower().replace(' ', '_').replace('&', 'and')}_user{i+1}@company.com"
                
                # Check if target exists
                target = Target.query.filter_by(email=email).first()
                if not target:
                    target = Target(
                        email=email,
                        first_name=f"User{i+1}",
                        last_name=sbu,
                        sbu=sbu,
                        position="Employee",
                        past_target=True
                    )
                    db.session.add(target)
                
                # Create result
                is_clicked = (i < clicked)
                is_reported = (i < reported)
                
                result = Result(
                    campaign_id=campaign.id,
                    email=email,
                    clicked=is_clicked,
                    reported=is_reported,
                    opened=True,
                    clicked_at=datetime.now() if is_clicked else None,
                    opened_at=datetime.now()
                )
                db.session.add(result)
                
                total_targeted += 1
                if is_clicked:
                    total_clicked += 1
                if is_reported:
                    total_reported += 1
        
        # Update campaign counts
        campaign.sent_count = total_targeted
        campaign.clicked_count = total_clicked
        
        db.session.commit()
        
        click_rate = (total_clicked / total_targeted * 100) if total_targeted > 0 else 0
        report_rate = (total_reported / total_targeted * 100) if total_targeted > 0 else 0
        
        log_audit(AuditActions.EDIT_CAMPAIGN, details=f"Updated historical data for '{campaign_name}'")
        
        return jsonify({
            'success': True,
            'campaign_id': campaign.id,
            'stats': {
                'targeted': total_targeted,
                'clicked': total_clicked,
                'reported': total_reported,
                'click_rate': round(click_rate, 2),
                'report_rate': round(report_rate, 2)
            }
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'error': str(e)})


@app.route('/api/historical_data/get/<int:campaign_id>')
@login_required
def get_historical_data(campaign_id):
    """Get historical campaign data for editing."""
    from utils.models import Campaign, Result, Target
    
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        return jsonify({'success': False, 'error': 'Campaign not found'})
    
    # Get results grouped by SBU
    results = Result.query.filter_by(campaign_id=campaign_id).all()
    
    sbu_stats = {}
    for result in results:
        target = get_target_for_result(result, campaign_id)
        sbu = target.sbu if target and target.sbu else 'Unknown'
        
        if sbu not in sbu_stats:
            sbu_stats[sbu] = {'targeted': 0, 'clicked': 0, 'reported': 0}
        
        sbu_stats[sbu]['targeted'] += 1
        if result.clicked:
            sbu_stats[sbu]['clicked'] += 1
        if getattr(result, 'reported', False):
            sbu_stats[sbu]['reported'] += 1
    
    sbu_data = [
        {
            'sbu': sbu,
            'targeted': stats['targeted'],
            'clicked': stats['clicked'],
            'reported': stats['reported']
        }
        for sbu, stats in sorted(sbu_stats.items())
    ]
    
    return jsonify({
        'success': True,
        'campaign': {
            'id': campaign.id,
            'name': campaign.name,
            'description': campaign.description,
            'date': campaign.created_at.strftime('%Y-%m') if campaign.created_at else ''
        },
        'sbu_data': sbu_data
    })


@app.route('/api/historical_data/delete/<int:campaign_id>', methods=['POST'])
@login_required
def delete_historical_data(campaign_id):
    """Delete a historical campaign."""
    from utils.models import Campaign, Result, db
    
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        return jsonify({'success': False, 'error': 'Campaign not found'})
    
    campaign_name = campaign.name
    
    # Delete results
    Result.query.filter_by(campaign_id=campaign_id).delete()
    
    # Delete campaign
    db.session.delete(campaign)
    db.session.commit()
    
    log_audit(AuditActions.DELETE_CAMPAIGN, details=f"Deleted historical campaign '{campaign_name}'")
    
    return jsonify({'success': True})

# ============================================

def _save_users_to_file():
    """Save users to a JSON file for persistence."""
    import json
    users_file = os.path.join(db_dir, 'users.json')
    data = {
        'users': {u: h for u, h in AUTHORIZED_USERS.items()},
        'admins': list(ADMIN_USERS)
    }
    with open(users_file, 'w') as f:
        json.dump(data, f, indent=2)

def _load_users_from_file():
    """Load users from JSON file."""
    import json
    users_file = os.path.join(db_dir, 'users.json')
    if os.path.exists(users_file):
        with open(users_file, 'r') as f:
            data = json.load(f)
            AUTHORIZED_USERS.update(data.get('users', {}))
            ADMIN_USERS.update(data.get('admins', []))

# Load saved users on startup
_load_users_from_file()


# ============== ANALYTICS & REPORTING ==============
@app.route('/analytics')
@login_required
def analytics_page():
    """Comprehensive analytics dashboard with granular controls."""
    from utils.models import Campaign
    
    # Get default SBUs from config
    try:
        from config import DEFAULT_SBUS
        default_sbus = DEFAULT_SBUS
    except ImportError:
        default_sbus = []
    
    # Get all campaigns for filters
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    
    return render_template('analytics.html', 
                          campaigns=campaigns,
                          default_sbus=default_sbus)


@app.route('/api/analytics/overview')
@login_required
def analytics_overview_api():
    """Get overview statistics with optional filters."""
    from utils.models import Campaign, Result, Target
    
    campaign_id = request.args.get('campaign_id', 'all')
    compare_id = request.args.get('compare_id', None)
    sbu_filter = request.args.getlist('sbu')  # Multiple SBUs
    
    def get_stats(cid, sbu_list=None):
        if cid == 'all':
            results = Result.query.all()
        else:
            results = Result.query.filter_by(campaign_id=int(cid)).all()
        
        # Filter by SBU if specified
        if sbu_list:
            filtered_results = []
            for r in results:
                target = get_target_for_result(r, int(cid) if cid != 'all' else None)
                if target and target.sbu in sbu_list:
                    filtered_results.append(r)
            results = filtered_results
        
        total = len(results)
        clicked = sum(1 for r in results if r.clicked)
        opened = sum(1 for r in results if r.opened)
        reported = sum(1 for r in results if getattr(r, 'reported', False))
        compromised = sum(1 for r in results if is_compromised(r))
        
        questionnaire_finished = sum(1 for r in results if getattr(r, 'questionnaire_completed', False))

        return {
            'total': total,
            'clicked': clicked,
            'opened': opened,
            'reported': reported,
            'compromised': compromised,
            'questionnaire_finished': questionnaire_finished,
            'click_rate': round((clicked / total * 100), 2) if total > 0 else 0,
            'open_rate': round((opened / total * 100), 2) if total > 0 else 0,
            'report_rate': round((reported / total * 100), 2) if total > 0 else 0,
            'compromise_rate': round((compromised / total * 100), 2) if total > 0 else 0,
            'questionnaire_rate': round((questionnaire_finished / total * 100), 2) if total > 0 else 0,
        }
    
    stats = get_stats(campaign_id, sbu_filter if sbu_filter else None)
    compare_stats = get_stats(compare_id, sbu_filter if sbu_filter else None) if compare_id else None
    
    # Calculate trends
    trends = None
    if compare_stats:
        def calc_trend(prev, curr):
            if prev == 0:
                return {'pct': None, 'direction': 'up' if curr > 0 else 'flat'}
            pct = round(((curr - prev) / prev * 100), 1)
            return {'pct': pct, 'direction': 'up' if pct > 0 else 'down' if pct < 0 else 'flat'}
        
        trends = {
            'total': calc_trend(compare_stats['total'], stats['total']),
            'click_rate': calc_trend(compare_stats['click_rate'], stats['click_rate']),
            'report_rate': calc_trend(compare_stats['report_rate'], stats['report_rate']),
            'compromise_rate': calc_trend(compare_stats['compromise_rate'], stats['compromise_rate'])
        }
    
    return jsonify({
        'success': True,
        'stats': stats,
        'compare_stats': compare_stats,
        'trends': trends
    })


@app.route('/api/analytics/sbu_breakdown')
@login_required
def analytics_sbu_breakdown_api():
    """Get detailed SBU breakdown with granular controls."""
    from utils.models import Campaign, Result, Target
    
    campaign_id = request.args.get('campaign_id', 'all')
    compare_id = request.args.get('compare_id', None)
    sort_by = request.args.get('sort_by', 'sbu')  # sbu, targeted, clicked, click_rate, etc.
    sort_order = request.args.get('sort_order', 'asc')
    
    def get_sbu_stats(cid):
        if cid == 'all':
            results = Result.query.all()
        else:
            results = Result.query.filter_by(campaign_id=int(cid)).all()
        
        sbu_data = {}
        for r in results:
            target = get_target_for_result(r, int(cid) if cid != 'all' else None)
            sbu = target.sbu if target and target.sbu else 'Unknown'
            
            if sbu not in sbu_data:
                sbu_data[sbu] = {
                    'targeted': 0, 'clicked': 0, 'opened': 0,
                    'reported': 0, 'compromised': 0
                }
            
            sbu_data[sbu]['targeted'] += 1
            if r.clicked:
                sbu_data[sbu]['clicked'] += 1
            if r.opened:
                sbu_data[sbu]['opened'] += 1
            if getattr(r, 'reported', False):
                sbu_data[sbu]['reported'] += 1
            if is_compromised(r):
                sbu_data[sbu]['compromised'] += 1
        
        # Calculate rates
        result_list = []
        for sbu, data in sbu_data.items():
            t = data['targeted']
            result_list.append({
                'sbu': sbu,
                'targeted': t,
                'clicked': data['clicked'],
                'opened': data['opened'],
                'reported': data['reported'],
                'compromised': data['compromised'],
                'click_rate': round((data['clicked'] / t * 100), 2) if t > 0 else 0,
                'open_rate': round((data['opened'] / t * 100), 2) if t > 0 else 0,
                'report_rate': round((data['reported'] / t * 100), 2) if t > 0 else 0,
                'compromise_rate': round((data['compromised'] / t * 100), 2) if t > 0 else 0
            })
        
        return result_list
    
    sbu_list = get_sbu_stats(campaign_id)
    compare_list = get_sbu_stats(compare_id) if compare_id else None
    
    # Merge comparison data if available
    if compare_list:
        compare_dict = {s['sbu']: s for s in compare_list}
        for sbu in sbu_list:
            if sbu['sbu'] in compare_dict:
                prev = compare_dict[sbu['sbu']]
                sbu['prev_click_rate'] = prev['click_rate']
                sbu['prev_report_rate'] = prev['report_rate']
                sbu['click_rate_change'] = round(sbu['click_rate'] - prev['click_rate'], 2)
                sbu['report_rate_change'] = round(sbu['report_rate'] - prev['report_rate'], 2)
    
    # Sort
    reverse = sort_order == 'desc'
    if sort_by in ['targeted', 'clicked', 'opened', 'reported', 'compromised', 
                   'click_rate', 'open_rate', 'report_rate', 'compromise_rate']:
        sbu_list.sort(key=lambda x: x.get(sort_by, 0), reverse=reverse)
    else:
        sbu_list.sort(key=lambda x: x.get('sbu', ''), reverse=reverse)
    
    # Calculate totals
    totals = {
        'targeted': sum(s['targeted'] for s in sbu_list),
        'clicked': sum(s['clicked'] for s in sbu_list),
        'opened': sum(s['opened'] for s in sbu_list),
        'reported': sum(s['reported'] for s in sbu_list),
        'compromised': sum(s['compromised'] for s in sbu_list)
    }
    t = totals['targeted']
    totals['click_rate'] = round((totals['clicked'] / t * 100), 2) if t > 0 else 0
    totals['open_rate'] = round((totals['opened'] / t * 100), 2) if t > 0 else 0
    totals['report_rate'] = round((totals['reported'] / t * 100), 2) if t > 0 else 0
    totals['compromise_rate'] = round((totals['compromised'] / t * 100), 2) if t > 0 else 0
    
    return jsonify({
        'success': True,
        'sbu_list': sbu_list,
        'totals': totals
    })


@app.route('/api/analytics/drilldown/<sbu>')
@login_required  
def analytics_drilldown_api(sbu):
    """Get individual target details for an SBU with filtering."""
    from utils.models import Campaign, Result, Target
    
    campaign_id = request.args.get('campaign_id', 'all')
    status_filter = request.args.get('status', 'all')  # all, clicked, reported, safe
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    
    # Get results
    if campaign_id == 'all':
        results = Result.query.all()
    else:
        results = Result.query.filter_by(campaign_id=int(campaign_id)).all()
    
    # Filter by SBU
    filtered = []
    for r in results:
        target = get_target_for_result(r, int(campaign_id) if campaign_id != 'all' else None)
        if target and target.sbu == sbu:
            # Apply status filter
            if status_filter == 'all':
                filtered.append((r, target))
            elif status_filter == 'clicked' and r.clicked:
                filtered.append((r, target))
            elif status_filter == 'reported' and getattr(r, 'reported', False):
                filtered.append((r, target))
            elif status_filter == 'safe' and not r.clicked and not is_compromised(r):
                filtered.append((r, target))
    
    # Pagination
    total = len(filtered)
    start = (page - 1) * per_page
    end = start + per_page
    paginated = filtered[start:end]
    
    # Build response
    targets = []
    for r, t in paginated:
        targets.append({
            'email': r.email,
            'first_name': t.first_name if t else '',
            'last_name': t.last_name if t else '',
            'position': t.position if t else '',
            'opened': r.opened,
            'clicked': r.clicked,
            'reported': getattr(r, 'reported', False),
            'compromised': is_compromised(r),
            'clicked_at': r.clicked_at.isoformat() if r.clicked_at else None,
            'opened_at': r.opened_at.isoformat() if r.opened_at else None
        })
    
    return jsonify({
        'success': True,
        'sbu': sbu,
        'targets': targets,
        'total': total,
        'page': page,
        'per_page': per_page,
        'pages': (total + per_page - 1) // per_page
    })


@app.route('/api/analytics/campaign_history')
@login_required
def analytics_campaign_history_api():
    """Return all campaigns with key stats for the timeline view."""
    from utils.models import Campaign, Result
    campaigns = Campaign.query.order_by(Campaign.created_at.asc()).all()
    history = []
    for c in campaigns:
        results = Result.query.filter_by(campaign_id=c.id).all()
        total = len(results)
        clicked = sum(1 for r in results if r.clicked)
        reported = sum(1 for r in results if getattr(r, 'reported', False))
        click_rate = round(clicked / total * 100, 1) if total > 0 else 0.0
        report_rate = round(reported / total * 100, 1) if total > 0 else 0.0
        history.append({
            'id': c.id,
            'name': c.name,
            'status': c.status,
            'created_at': c.created_at.strftime('%d %b %Y') if c.created_at else '—',
            'total': total,
            'click_rate': click_rate,
            'report_rate': report_rate,
        })
    return jsonify({'success': True, 'history': history})


@app.route('/api/analytics/export')
@login_required
def analytics_export_api():
    """Export analytics data with granular options."""
    from flask import Response
    from utils.models import Campaign, Result, Target
    import csv
    from io import StringIO
    
    campaign_id = request.args.get('campaign_id', 'all')
    export_type = request.args.get('type', 'sbu')  # sbu, targets, full
    sbu_filter = request.args.getlist('sbu')
    
    output = StringIO()
    writer = csv.writer(output)
    
    # Get results
    if campaign_id == 'all':
        results = Result.query.all()
        filename = 'analytics_all_campaigns'
    else:
        results = Result.query.filter_by(campaign_id=int(campaign_id)).all()
        campaign = Campaign.query.get(int(campaign_id))
        filename = f'analytics_{campaign.name.replace(" ", "_")}' if campaign else f'analytics_{campaign_id}'
    
    if export_type == 'sbu':
        writer.writerow(['SBU', 'Targeted', 'Opened', 'Open Rate %', 'Clicked', 'Click Rate %', 
                        'Reported', 'Report Rate %', 'Compromised', 'Compromise Rate %'])
        
        sbu_data = {}
        for r in results:
            target = get_target_for_result(r, int(campaign_id) if campaign_id != 'all' else None)
            sbu = target.sbu if target and target.sbu else 'Unknown'
            
            if sbu_filter and sbu not in sbu_filter:
                continue
            
            if sbu not in sbu_data:
                sbu_data[sbu] = {'targeted': 0, 'clicked': 0, 'opened': 0, 'reported': 0, 'compromised': 0}
            
            sbu_data[sbu]['targeted'] += 1
            if r.clicked: sbu_data[sbu]['clicked'] += 1
            if r.opened: sbu_data[sbu]['opened'] += 1
            if getattr(r, 'reported', False): sbu_data[sbu]['reported'] += 1
            if is_compromised(r): sbu_data[sbu]['compromised'] += 1

        for sbu, data in sorted(sbu_data.items()):
            t = data['targeted']
            writer.writerow([
                sbu, t, data['opened'], round((data['opened']/t*100), 2) if t > 0 else 0,
                data['clicked'], round((data['clicked']/t*100), 2) if t > 0 else 0,
                data['reported'], round((data['reported']/t*100), 2) if t > 0 else 0,
                data['compromised'], round((data['compromised']/t*100), 2) if t > 0 else 0
            ])
    
    elif export_type == 'targets':
        writer.writerow(['Email', 'First Name', 'Last Name', 'SBU', 'Position', 
                        'Opened', 'Clicked', 'Reported', 'Compromised', 'Clicked At'])
        
        for r in results:
            target = get_target_for_result(r, int(campaign_id) if campaign_id != 'all' else None)
            sbu = target.sbu if target else ''
            
            if sbu_filter and sbu not in sbu_filter:
                continue
            
            writer.writerow([
                r.email,
                target.first_name if target else '',
                target.last_name if target else '',
                sbu,
                target.position if target else '',
                'Yes' if r.opened else 'No',
                'Yes' if r.clicked else 'No',
                'Yes' if getattr(r, 'reported', False) else 'No',
                'Yes' if is_compromised(r) else 'No',
                r.clicked_at.strftime('%Y-%m-%d %H:%M:%S') if r.clicked_at else ''
            ])
    
    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}_{export_type}.csv'}
    )


# ============== CAMPAIGN REPORT GENERATION ==============
@app.route('/report/<int:campaign_id>')
@login_required
def campaign_report_page(campaign_id):
    """Render campaign report (HTML) with comparison to previous campaign."""
    from utils.models import Campaign, Result, Target, EmailTemplate
    
    # 1. Get Primary Campaign
    campaign = Campaign.query.get_or_404(campaign_id)
    
    # 2. Get Comparison Campaign
    compare_id = request.args.get('compare_with')
    prev_campaign = None
    
    # 3. Get All Templates (for manual selection)
    all_templates = EmailTemplate.query.all()
    
    if compare_id and compare_id.lower() != 'none':
        prev_campaign = Campaign.query.get(int(compare_id))
    elif compare_id is None:
        # Default to previous by date if not specified
        prev_campaign = Campaign.query.filter(Campaign.created_at < campaign.created_at)\
                                      .order_by(Campaign.created_at.desc()).first()

    def build_stats(camp):
        if not camp: return None
        results = Result.query.filter_by(campaign_id=camp.id).all()
        total = len(results)
        # If no results found via campaign_id, try matching by email/time (legacy support)
        if total == 0:
             # Fallback logic if needed, or just return 0s
             pass

        clicked = sum(1 for r in results if r.clicked)
        opened = sum(1 for r in results if r.opened)
        reported = sum(1 for r in results if getattr(r, 'reported', False))
        compromised = sum(1 for r in results if is_compromised(r))
        
        # Calculate rates
        click_rate = round((clicked/total*100), 2) if total > 0 else 0.0
        open_rate = round((opened/total*100), 2) if total > 0 else 0.0
        report_rate = round((reported/total*100), 2) if total > 0 else 0.0
        compromise_rate = round((compromised/total*100), 2) if total > 0 else 0.0

        # SBU Breakdown
        sbu_stats = {}
        # Get all targets for this campaign to ensure we count non-interactions too
        # (Assuming Result is created for every Target. If not, we need Target query)
        # For now, using Result as primary source
        
        for r in results:
            # First try campaign-specific target, then fall back to global target
            t = Target.query.filter_by(campaign_id=camp.id, email=r.email).first()
            if not t:
                t = Target.query.filter_by(campaign_id=None, email=r.email).first()
            sbu_name = (t.sbu if t and t.sbu else 'Unknown').strip()
            
            if sbu_name not in sbu_stats:
                sbu_stats[sbu_name] = {'targeted': 0, 'clicked': 0, 'opened': 0, 'reported': 0, 'compromised': 0}
            
            sbu_stats[sbu_name]['targeted'] += 1
            if r.clicked: sbu_stats[sbu_name]['clicked'] += 1
            if r.opened: sbu_stats[sbu_name]['opened'] += 1
            if getattr(r, 'reported', False): sbu_stats[sbu_name]['reported'] += 1
            if is_compromised(r): sbu_stats[sbu_name]['compromised'] += 1

        sbu_list = []
        for name, data in sbu_stats.items():
            t = data['targeted']
            o_rate = round((data['opened']/t*100), 2) if t > 0 else 0.0
            c_rate = round((data['clicked']/t*100), 2) if t > 0 else 0.0
            r_rate = round((data['reported']/t*100), 2) if t > 0 else 0.0
            comp_rate = round((data['compromised']/t*100), 2) if t > 0 else 0.0
            
            sbu_list.append({
                'sbu': name,
                'targeted': t,
                'opened': data['opened'],
                'clicked': data['clicked'],
                'reported': data['reported'],
                'compromised': data['compromised'],
                'open_rate': o_rate,
                'click_rate': c_rate,
                'report_rate': r_rate,
                'compromise_rate': comp_rate
            })
        
        # Sort by click rate descending (highest risk first)
        sbu_list.sort(key=lambda x: x['click_rate'], reverse=True)

        # Reporters List (Explicitly for this campaign)
        reporters = []
        for r in results:
            if getattr(r, 'reported', False):
                # First try campaign-specific target, then fall back to global target
                t = Target.query.filter_by(campaign_id=camp.id, email=r.email).first()
                if not t:
                    t = Target.query.filter_by(campaign_id=None, email=r.email).first()
                reporters.append({
                    'email': r.email,
                    'name': f"{t.first_name} {t.last_name}" if t and t.first_name else r.email.split('@')[0]
                })

        return {
            'total': total,
            'opened': opened,
            'clicked': clicked,
            'reported': reported,
            'compromised': compromised,
            'open_rate': open_rate,
            'click_rate': click_rate,
            'report_rate': report_rate,
            'compromise_rate': compromise_rate,
            'sbu_list': sbu_list,
            'reporters': reporters
        }

    stats = build_stats(campaign)
    prev_stats = build_stats(prev_campaign)

    # --- Smart Narrative Generation ---
    narrative = {
        'summary': "",
        'critical': [],
        'positive': [],
        'actions': []
    }
    
    # 1. Executive Summary & Trend
    theme = campaign.subject or "Security Alert"
    trend_msg = "Results show consistent performance."
    if prev_stats:
        diff = prev_stats['click_rate'] - stats['click_rate']
        if diff > 5:
            trend_msg = "Results indicate a significant improvement in threat recognition with a drastic reduction in click-through rates."
        elif diff < -5:
            trend_msg = "Results indicate a decline in vigilance compared to the previous campaign."
            
    narrative['summary'] = f"This campaign utilized a \"{theme}\" theme. {trend_msg}"

    # 2. Critical Findings
    if stats['click_rate'] > 15:
        narrative['critical'].append(f"High click rate ({stats['click_rate']}%) suggests the '{theme}' lure was highly effective or user vigilance is currently low.")
    elif stats['clicked'] > 0:
        narrative['critical'].append(f"While the click rate is low, {stats['clicked']} users still clicked, indicating a need for specific training on this lure type.")
    
    if stats['compromised'] > 0:
        narrative['critical'].append(f"{stats['compromised']} users entered credentials, representing a critical security risk.")

    # 3. Positive Notes
    if stats['report_rate'] > 10:
        narrative['positive'].append(f"Strong reporting culture observed with {stats['report_rate']}% of users reporting the email.")
    if stats['click_rate'] < 5 and stats['total'] > 10:
        narrative['positive'].append(f"Low click rate ({stats['click_rate']}%) against a sample of {stats['total']} users indicates strong adherence to core security principles.")

    # 4. Immediate Actions
    high_risk = [s['sbu'] for s in stats['sbu_list'] if s['click_rate'] > 0]
    if high_risk:
        narrative['actions'].append(f"Department-wide training for {', '.join(high_risk[:3])} to address elevated risk percentages.")
    if stats['clicked'] > 0:
        narrative['actions'].append(f"Mandatory re-training for all {stats['clicked']} employees who clicked the link.")

    # Get landing page submissions if campaign used a landing page
    from utils.models import LandingPageSubmission
    submissions = []
    if campaign.landing_page_id:
        submissions = LandingPageSubmission.query.filter_by(campaign_id=campaign.id).order_by(LandingPageSubmission.submitted_at.desc()).all()

    all_campaigns = Campaign.query.filter(Campaign.id != campaign.id).order_by(Campaign.created_at.desc()).all()

    return render_template('campaign_report.html',
                           campaign=campaign,
                           prev_campaign=prev_campaign,
                           stats=stats,
                           prev_stats=prev_stats,
                           narrative=narrative,
                           all_templates=all_templates,
                           all_campaigns=all_campaigns,
                           landing_page_submissions=submissions)


# ============== PDF EXPORT ==============
_WKHTMLTOPDF = r'C:\Program Files\wkhtmltopdf\bin\wkhtmltopdf.exe'

@app.route('/report/<int:campaign_id>/export_pdf')
@login_required
def export_campaign_report_pdf(campaign_id):
    """Export the campaign report as a PDF using wkhtmltopdf."""
    import subprocess, tempfile
    from utils.models import Campaign
    campaign = Campaign.query.get_or_404(campaign_id)
    if not os.path.exists(_WKHTMLTOPDF):
        return jsonify({'error': 'wkhtmltopdf not found'}), 500
    try:
        # Build the internal URL for the report page (use HTTP with session cookie)
        report_url = url_for('campaign_report_page', campaign_id=campaign_id, _external=True)
        # Use a temp file for output
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tf:
            out_path = tf.name
        # Build cookie header so wkhtmltopdf can access the auth-protected route
        session_cookie = request.cookies.get('session', '')
        cookie_str = f'session={session_cookie}'
        cmd = [
            _WKHTMLTOPDF,
            '--page-size', 'A4',
            '--orientation', 'Landscape',
            '--margin-top', '10mm',
            '--margin-bottom', '10mm',
            '--margin-left', '10mm',
            '--margin-right', '10mm',
            '--print-media-type',
            '--no-background',
            '--cookie', 'session', session_cookie,
            '--javascript-delay', '1500',
            '--quiet',
            report_url,
            out_path,
        ]
        result = subprocess.run(cmd, capture_output=True, timeout=60)
        if result.returncode != 0:
            err = result.stderr.decode('utf-8', errors='replace')
            app.logger.error(f'wkhtmltopdf error: {err}')
            return jsonify({'error': 'PDF generation failed', 'detail': err}), 500

        with open(out_path, 'rb') as fh:
            pdf_bytes = fh.read()
        os.unlink(out_path)

        from flask import Response
        safe_name = campaign.name.replace(' ', '_').replace('/', '-')
        filename = f'campaign_report_{safe_name}.pdf'
        return Response(
            pdf_bytes,
            mimetype='application/pdf',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'PDF export timed out'}), 504
    except Exception as e:
        app.logger.exception('PDF export error')
        return jsonify({'error': str(e)}), 500


# ============== LANDING PAGE DESIGNER ==============
@app.route('/landing-pages')
@login_required
def landing_pages():
    """Landing page designer - list all pages or return JSON for API calls."""
    from utils.models import LandingPage
    pages = LandingPage.query.order_by(LandingPage.updated_at.desc()).all()
    
    # Check if this is an API request (fetch) or browser navigation
    if request.headers.get('Accept', '').startswith('application/json') or request.is_json:
        return jsonify([{
            'id': p.id,
            'name': p.name,
            'page_type': p.page_type,
            'html_content': p.html_content,
            'capture_data': p.capture_data,
            'redirect_url': p.redirect_url,
            'created_at': p.created_at.isoformat() if p.created_at else None,
            'updated_at': p.updated_at.isoformat() if p.updated_at else None
        } for p in pages])
    
    return render_template('landing_pages.html', landing_pages=pages)


@app.route('/landing-pages/create', methods=['POST'])
@login_required
def create_landing_page():
    """Create a new landing page."""
    from utils.models import LandingPage, db
    import json
    
    try:
        data = request.get_json(silent=True) or {}
        
        name = data.get('name', '').strip()
        if not name:
            return jsonify({'success': False, 'error': 'Page name is required'}), 400
        
        page = LandingPage(
            name=name,
            page_type=data.get('page_type', 'credential_harvest'),
            html_content=data.get('html_content', ''),
            custom_css=data.get('custom_css'),
            questions=json.dumps(data.get('questions', [])),
            capture_data=data.get('capture_data', True),
            redirect_url=data.get('redirect_url')
        )
        
        db.session.add(page)
        db.session.commit()
        
        log_audit(AuditActions.CREATE, f"Created landing page: {page.name}", 'landing_page', page.id)
        
        return jsonify({'success': True, 'id': page.id})
    except Exception as e:
        app.logger.exception(f"Error creating landing page: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/landing-pages/update', methods=['POST'])
@login_required
def update_landing_page():
    """Update an existing landing page."""
    from utils.models import LandingPage, db
    import json
    
    try:
        data = request.get_json(silent=True) or {}
        page_id = data.get('page_id')
        
        if not page_id:
            return jsonify({'success': False, 'error': 'page_id is required'}), 400
        
        page = LandingPage.query.get(int(page_id))
        if not page:
            return jsonify({'success': False, 'error': f'Landing page {page_id} not found'}), 404
        
        page.name = data.get('name', page.name)
        page.page_type = data.get('page_type', page.page_type)
        page.html_content = data.get('html_content', page.html_content)
        page.custom_css = data.get('custom_css', page.custom_css)
        page.questions = json.dumps(data.get('questions', []))
        page.capture_data = data.get('capture_data', True)
        page.redirect_url = data.get('redirect_url')
        page.updated_at = datetime.now()
        
        db.session.commit()
        
        log_audit(AuditActions.UPDATE, f"Updated landing page: {page.name}", 'landing_page', page.id)
        
        return jsonify({'success': True})
    except Exception as e:
        app.logger.exception(f"Error updating landing page: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/landing-pages/<int:page_id>')
@login_required
def get_landing_page(page_id):
    """Get landing page details."""
    from utils.models import LandingPage
    import json
    
    page = LandingPage.query.get_or_404(page_id)
    
    return jsonify({
        'id': page.id,
        'name': page.name,
        'page_type': page.page_type,
        'html_content': page.html_content,
        'custom_css': page.custom_css,
        'questions': json.loads(page.questions) if page.questions else [],
        'capture_data': page.capture_data,
        'redirect_url': page.redirect_url
    })


@app.route('/landing-pages/<int:page_id>/preview')
@login_required
def preview_landing_page(page_id):
    """Preview a landing page."""
    from utils.models import LandingPage
    
    page = LandingPage.query.get_or_404(page_id)
    
    html = page.html_content or ''
    if page.custom_css:
        html = html.replace('</head>', f'<style>{page.custom_css}</style></head>')
    
    # Replace placeholders for preview
    html = html.replace('{{email}}', 'preview@example.com')
    html = html.replace('{{tracking_pixel}}', '<!-- Tracking Pixel -->')
    
    return html


@app.route('/landing-pages/<int:page_id>/duplicate', methods=['POST'])
@login_required
def duplicate_landing_page(page_id):
    """Duplicate a landing page."""
    from utils.models import LandingPage, db
    
    original = LandingPage.query.get_or_404(page_id)
    
    duplicate = LandingPage(
        name=f"{original.name} (Copy)",
        page_type=original.page_type,
        html_content=original.html_content,
        custom_css=original.custom_css,
        questions=original.questions,
        capture_data=original.capture_data,
        redirect_url=original.redirect_url
    )
    
    db.session.add(duplicate)
    db.session.commit()
    
    log_audit(AuditActions.CREATE, f"Duplicated landing page: {original.name}", 'landing_page', duplicate.id)
    
    return jsonify({'success': True, 'id': duplicate.id})


@app.route('/landing-pages/<int:page_id>/delete', methods=['POST'])
@login_required
def delete_landing_page(page_id):
    """Delete a landing page."""
    from utils.models import LandingPage, db
    
    page = LandingPage.query.get_or_404(page_id)
    page_name = page.name
    
    db.session.delete(page)
    db.session.commit()
    
    log_audit(AuditActions.DELETE, f"Deleted landing page: {page_name}", 'landing_page', page_id)
    
    return jsonify({'success': True})


@app.route('/landing/<int:page_id>', methods=['GET'])
def landing_page_redirect(page_id):
    """Backwards compatibility route for old email links that use /landing/<id>?email=...&campaign_id=..."""
    from utils.models import Result
    
    email = request.args.get('email')
    campaign_id = request.args.get('campaign_id')
    
    app.logger.info(f"Old format link accessed: /landing/{page_id}?email={email}&campaign_id={campaign_id}")
    
    # Try to find the Result by email and campaign_id to get the token
    if email and campaign_id:
        result = Result.query.filter_by(email=email, campaign_id=campaign_id).first()
        if result and result.token:
            # Redirect to the new format with token
            new_url = f"/landing/{page_id}/submit?token={result.token}"
            app.logger.info(f"Redirecting to new format: {new_url}")
            return redirect(new_url)
    
    # If we can't find the token, show a friendly error
    return f"""
    <html>
    <head><title>Link Error</title></head>
    <body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
        <h2>⚠️ Invalid or Expired Link</h2>
        <p>This link appears to be invalid or has expired.</p>
        <p>If you received this link in an email, please contact the Information Security Team.</p>
    </body>
    </html>
    """, 404


@app.route('/landing/<int:page_id>/submit', methods=['GET', 'POST'])
def landing_page_submit(page_id):
    """Handle landing page form submissions (public endpoint for campaigns)."""
    from utils.models import LandingPage, LandingPageSubmission, Result, db
    import json
    from datetime import datetime
    
    page = LandingPage.query.get_or_404(page_id)
    
    # Track click if token is provided
    token = request.args.get('token')
    email_param = request.args.get('email')
    campaign_id_param = request.args.get('campaign_id')
    
    app.logger.info(f"Landing page {page_id} accessed: method={request.method}, token={token}, email={email_param}, campaign_id={campaign_id_param}")
    
    if token:
        try:
            result = Result.query.filter_by(token=token).first()
            app.logger.info(f"Token lookup: token={token}, found={result is not None}")
            if result:
                # Track click
                result.clicked = True
                if not result.clicked_at:
                    result.clicked_at = datetime.now()
                # Also track open - if they clicked, they must have opened the email!
                if not result.opened:
                    result.opened = True
                    result.opened_at = datetime.now()
                    app.logger.info(f"Auto-tracked open for token {token} (clicked implies opened)")
                db.session.commit()
                app.logger.info(f"Click tracked for token {token}, email={result.email}")
            else:
                app.logger.warning(f"Token {token} not found in database!")
        except Exception as e:
            app.logger.error(f"Failed to track click for token {token}: {e}")
    
    if request.method == 'GET':
        # Render the landing page
        html = page.html_content or ''
        if page.custom_css:
            html = html.replace('</head>', f'<style>{page.custom_css}</style></head>')
        
        # Get email and campaign_id from query params OR from token lookup
        email = request.args.get('email', '')
        campaign_id = request.args.get('campaign_id', '')
        token = request.args.get('token', '')
        
        # If we have token but no email/campaign_id, look them up
        if token and (not email or not campaign_id):
            result = Result.query.filter_by(token=token).first()
            if result:
                email = result.email
                campaign_id = str(result.campaign_id)
                app.logger.info(f"Token lookup for GET: token={token}, email={email}, campaign_id={campaign_id}")
        
        # Replace placeholders
        html = html.replace('{{email}}', email)
        
        # Add tracking pixel using token for proper open tracking
        # The /pixel endpoint handles the database update for opened status
        if token:
            tracking_pixel = f'<img src="/pixel?token={token}" width="1" height="1" style="display:none;"/>'
            html = html.replace('{{tracking_pixel}}', tracking_pixel)
        elif campaign_id and email:
            # Fallback: try to find token from Result table
            result = Result.query.filter_by(campaign_id=int(campaign_id), email=email).first()
            if result and result.token:
                tracking_pixel = f'<img src="/pixel?token={result.token}" width="1" height="1" style="display:none;"/>'
                html = html.replace('{{tracking_pixel}}', tracking_pixel)
            else:
                html = html.replace('{{tracking_pixel}}', '')
        else:
            html = html.replace('{{tracking_pixel}}', '')
        
        # Inject submission script for questionnaire pages
        # This adds the actual POST functionality to the page
        # Now works with token-only links too!
        if token or (campaign_id and email):
            submission_script = f'''
<script>
// Phishing simulation submission handler - MUST run on button click
(function() {{
    const campaignId = '{campaign_id}';
    const userEmail = '{email}';
    const userToken = '{token}';
    const submitUrl = '/landing/{page_id}/submit?token=' + userToken;
    let submitted = false;
    
    function submitToServer() {{
        if (submitted) return;
        
        // Collect all answers - supports multiple question formats
        const answers = {{}};
        let score = 0;
        
        // Method 1: Find question-cards with data-question and selected options with data-option
        const questionCards = document.querySelectorAll('.question-card[data-question]');
        questionCards.forEach(function(card) {{
            const qNum = card.getAttribute('data-question');
            const qText = card.querySelector('h3')?.textContent?.trim() || 'Question ' + qNum;
            
            // Find selected option (has .selected class)
            const selectedOption = card.querySelector('.option.selected');
            
            // Find correct answer from the correct-answer div
            const correctAnswerDiv = card.querySelector('.correct-answer');
            const correctAnswer = correctAnswerDiv ? correctAnswerDiv.getAttribute('data-correct') : null;
            
            if (selectedOption) {{
                const answerLetter = selectedOption.getAttribute('data-option') || '';
                const answerText = selectedOption.textContent?.trim() || '';
                
                // Check if answer is correct
                const isCorrect = answerLetter === correctAnswer;
                if (isCorrect) {{
                    score++;
                }}
                
                answers['q' + qNum] = {{
                    question: qText.substring(0, 200),
                    answer: answerLetter,
                    text: answerText.substring(0, 500),
                    correct: isCorrect
                }};
            }}
        }});
        
        // Method 2: Try .question containers with radio buttons (fallback)
        if (Object.keys(answers).length === 0) {{
            const questions = document.querySelectorAll('.question');
            questions.forEach(function(q, idx) {{
                const qNum = idx + 1;
                const qText = q.querySelector('h3')?.textContent?.trim() || 'Question ' + qNum;
                
                const selectedRadio = q.querySelector('input[type="radio"]:checked');
                if (selectedRadio) {{
                    const optionDiv = selectedRadio.closest('.option');
                    const label = optionDiv?.querySelector('label') || document.querySelector('label[for="' + selectedRadio.id + '"]');
                    const selectedAnswer = label?.textContent?.trim() || selectedRadio.value;
                    const radioId = selectedRadio.id || '';
                    const match = radioId.match(/[a-d]$/i);
                    
                    answers['q' + qNum] = {{
                        question: qText.substring(0, 200),
                        answer: match ? match[0].toUpperCase() : selectedRadio.value,
                        text: selectedAnswer
                    }};
                }}
            }});
        }}
        
        // Method 3: Fallback to form inputs
        if (Object.keys(answers).length === 0) {{
            const form = document.querySelector('form');
            if (form) {{
                for (let i = 1; i <= 10; i++) {{
                    const selectedRadio = form.querySelector('input[name="q' + i + '"]:checked');
                    if (selectedRadio) {{
                        const label = document.querySelector('label[for="' + selectedRadio.id + '"]');
                        const radioId = selectedRadio.id || '';
                        const match = radioId.match(/[a-d]$/i);
                        answers['q' + i] = {{
                            answer: match ? match[0].toUpperCase() : selectedRadio.value,
                            text: label?.textContent?.trim() || selectedRadio.value
                        }};
                    }}
                }}
            }}
        }}
        
        // If we still don't have a score, try to read from the page's score display
        if (score === 0) {{
            const scoreEl = document.querySelector('#scoreValue');
            if (scoreEl && scoreEl.textContent) {{
                score = parseInt(scoreEl.textContent) || 0;
            }}
        }}
        
        // Get total questions count
        const totalQuestions = questionCards.length || Object.keys(answers).length || 6;
        
        console.log('[PhishSim] Submitting assessment: email=' + userEmail + ', campaign=' + campaignId + ', score=' + score + '/' + totalQuestions);
        console.log('[PhishSim] Answers captured:', answers);
        
        const formData = new FormData();
        formData.append('email', userEmail);
        formData.append('campaign_id', campaignId);
        formData.append('score', score);
        formData.append('total_questions', totalQuestions);
        formData.append('answers', JSON.stringify(answers));
        
        fetch(submitUrl, {{
            method: 'POST',
            body: formData
        }}).then(function(response) {{
            console.log('[PhishSim] Assessment submitted successfully to server');
            submitted = true;
        }}).catch(function(err) {{
            console.error('Submission error:', err);
        }});
    }}
    
    // Use capturing phase to catch clicks before page scripts
    document.addEventListener('click', function(e) {{
        const t = e.target;
        console.log('[PhishSim] Click detected on:', t.tagName, t.id, t.className);
        if (t.id === 'submitBtn' || t.classList.contains('submit-btn') || 
            (t.tagName === 'BUTTON' && (t.textContent.includes('Submit') || t.textContent.includes('Assessment')))) {{
            console.log('[PhishSim] Submit button clicked - will submit in 1.5s');
            // Wait for the page's own handler to finish processing and showing results
            setTimeout(submitToServer, 1500);
        }}
    }}, true);
    
    // Backup: Watch for score display to become visible (indicates form was processed)
    const observer = new MutationObserver(function(mutations) {{
        const scoreDisplay = document.getElementById('scoreDisplay');
        const completionMsg = document.getElementById('completionMessage');
        if ((scoreDisplay && scoreDisplay.classList.contains('show')) || 
            (completionMsg && completionMsg.classList.contains('show'))) {{
            console.log('[PhishSim] Score/completion displayed - submitting to server');
            setTimeout(submitToServer, 500);
            observer.disconnect();
        }}
    }});
    observer.observe(document.body, {{ attributes: true, subtree: true, attributeFilter: ['class'] }});
    
    // Fallback: Also hook into the page's own submit button directly after DOM ready
    setTimeout(function() {{
        const btn = document.getElementById('submitBtn');
        if (btn) {{
            console.log('[PhishSim] Found submitBtn, adding direct click handler');
            btn.addEventListener('click', function() {{
                console.log('[PhishSim] Direct click handler fired');
                setTimeout(submitToServer, 2000);
            }});
        }}
    }}, 100);
}})();
</script>
'''
            # Inject before </body>
            html = html.replace('</body>', submission_script + '</body>')
        
        return html
    
    elif request.method == 'POST':
        # Handle form submission
        email = request.form.get('email') or request.args.get('email', '')
        campaign_id = request.form.get('campaign_id') or request.args.get('campaign_id')
        token = request.args.get('token', '')
        score = request.form.get('score')  # For questionnaire scoring
        
        app.logger.info(f"Landing page POST received: email={email}, campaign_id={campaign_id}, token={token}, score={score}")
        
        if page.capture_data:
            # Collect all form data
            form_data = {}
            for key, value in request.form.items():
                if key not in ['email', 'campaign_id', 'score']:
                    form_data[key] = value
            
            # Save submission
            submission = LandingPageSubmission(
                landing_page_id=page.id,
                campaign_id=int(campaign_id) if campaign_id else None,
                email=email,
                submitted_data=json.dumps(form_data),
                ip_address=request.remote_addr,
                user_agent=request.headers.get('User-Agent', '')
            )
            
            db.session.add(submission)
            db.session.commit()
            
            try:
                log_metric('landing_page_submission', 
                           int(campaign_id) if campaign_id else 0, 
                           email or '', 
                           token or '', 
                           {'landing_page_id': page.id, 'form_data': form_data, 'ip_address': request.remote_addr, 'user_agent': request.headers.get('User-Agent', '')})
            except Exception as e:
                app.logger.error(f"Failed to log metric landing_page_submission: {e}")
        
        # Mark questionnaire as completed in Result if this is a campaign
        result = None
        
        # First try to find by token (most reliable)
        if token:
            from utils.models import Result
            result = Result.query.filter_by(token=token).first()
            if result:
                app.logger.info(f"Found result by token={token}, email={result.email}")
                email = result.email  # Use email from result
                campaign_id = result.campaign_id
        
        # Fallback to email+campaign_id lookup
        if not result and campaign_id and email:
            from utils.models import Result
            result = Result.query.filter_by(
                campaign_id=int(campaign_id),
                email=email
            ).first()
            app.logger.info(f"Looking for result with campaign_id={campaign_id}, email={email}, found={result is not None}")
        
        # Update result if found
        if result:
            result.questionnaire_completed = True
            result.questionnaire_completed_at = datetime.now()
            
            # Save answers JSON - first try the 'answers' field from injected script
            answers_json = request.form.get('answers')
            
            # If no answers field, build from individual q1, q2, etc. form fields
            user_answers = {}
            if not answers_json:
                for i in range(1, 20):  # Support up to 20 questions
                    q_key = f'q{i}'
                    q_value = request.form.get(q_key)
                    if q_value:
                        user_answers[q_key] = {
                            'answer': q_value,
                            'text': q_value  # The value itself (correct, wrong1, etc.)
                        }
                if user_answers:
                    import json
                    answers_json = json.dumps(user_answers)
            else:
                # Parse existing answers_json to get user_answers dict
                try:
                    import json
                    user_answers = json.loads(answers_json)
                except:
                    user_answers = {}
            
            # Calculate score server-side based on landing page's correct answers
            calculated_score = None
            if page.questions:
                try:
                    import json
                    questions = json.loads(page.questions)
                    total_questions = len(questions)
                    correct_count = 0
                    
                    # Compare user answers with correct answers from landing page
                    for idx, question in enumerate(questions):
                        q_key = f'q{idx + 1}'
                        correct_answer = question.get('correct', '')
                        
                        # Get user's answer
                        user_answer = None
                        if q_key in user_answers:
                            if isinstance(user_answers[q_key], dict):
                                user_answer = user_answers[q_key].get('answer', '')
                            else:
                                user_answer = user_answers[q_key]
                        
                        # Check if correct
                        if user_answer and user_answer.upper() == correct_answer.upper():
                            correct_count += 1
                        
                        # Update user_answers with correct/incorrect flag
                        if q_key in user_answers:
                            if isinstance(user_answers[q_key], dict):
                                user_answers[q_key]['correct'] = (user_answer.upper() == correct_answer.upper())
                                user_answers[q_key]['correct_answer'] = correct_answer
                            else:
                                user_answers[q_key] = {
                                    'answer': user_answer,
                                    'correct': (user_answer.upper() == correct_answer.upper()),
                                    'correct_answer': correct_answer
                                }
                    
                    # Calculate percentage
                    if total_questions > 0:
                        calculated_score = int((correct_count / total_questions) * 100)
                        app.logger.info(f"Calculated score: {correct_count}/{total_questions} = {calculated_score}%")
                    
                    # Update answers_json with corrected data
                    answers_json = json.dumps(user_answers)
                except Exception as e:
                    app.logger.error(f"Error calculating score: {e}")
            
            # Use calculated score if available, otherwise use submitted score
            if calculated_score is not None:
                result.questionnaire_score = calculated_score
            elif score:
                try:
                    result.questionnaire_score = int(score)
                except:
                    pass
            
            if answers_json:
                result.questionnaire_answers = answers_json
                app.logger.info(f"Saved answers for {email}: {answers_json[:200]}...")
            
            result.compromised = True  # They submitted data
            db.session.commit()
            app.logger.info(f"Questionnaire marked complete for {email}, score={result.questionnaire_score}")
            log_metric('submitted', result.campaign_id, email, token, {'score': result.questionnaire_score, 'answers': answers_json})
        else:
            app.logger.warning(f"No result found for email={email}, campaign_id={campaign_id}, token={token}")
        
        # Check if AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or request.content_type == 'application/json':
            return jsonify({'success': True, 'message': 'Assessment submitted successfully'})
        
        # Redirect to specified URL or show thank you message
        if page.redirect_url:
            return redirect(page.redirect_url)
        else:
            return '<html><body><h2>Thank you for your submission.</h2></body></html>'


# ============== SMTP PROFILES ==============
@app.route('/smtp-profiles')
@login_required
def smtp_profiles_api():
    """SMTP profiles list as JSON API - for templates page dropdown."""
    from utils.models import SMTPProfile
    profiles = SMTPProfile.query.order_by(SMTPProfile.is_default.desc(), SMTPProfile.name).all()
    return jsonify([{
        'id': p.id,
        'name': p.name,
        'smtp_server': p.smtp_server,
        'smtp_port': p.smtp_port,
        'is_default': p.is_default
    } for p in profiles])


@app.route('/settings/smtp')
@login_required
def smtp_profiles():
    """SMTP profiles management page."""
    from utils.models import SMTPProfile
    profiles = SMTPProfile.query.order_by(SMTPProfile.is_default.desc(), SMTPProfile.name).all()
    return render_template('smtp_profiles.html', profiles=profiles)


@app.route('/settings/smtp/create', methods=['POST'])
@login_required
def create_smtp_profile():
    """Create a new SMTP profile."""
    from utils.models import SMTPProfile, db
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        # Validate required fields
        if not data.get('name'):
            return jsonify({'success': False, 'error': 'Profile name is required'}), 400
        if not data.get('smtp_server'):
            return jsonify({'success': False, 'error': 'SMTP server is required'}), 400
        if not data.get('sender_email'):
            return jsonify({'success': False, 'error': 'Sender email is required'}), 400
        
        # If this is being set as default, unset other defaults
        if data.get('is_default'):
            SMTPProfile.query.filter_by(is_default=True).update({'is_default': False})
        
        profile = SMTPProfile(
            name=data['name'],
            smtp_server=data['smtp_server'],
            smtp_port=int(data.get('smtp_port', 25)),
            smtp_user=data.get('smtp_user'),
            smtp_password=data.get('smtp_password'),
            sender_name=data.get('sender_name'),
            sender_email=data['sender_email'],
            from_name=data.get('from_name'),
            reply_to=data.get('reply_to'),
            custom_headers=data.get('custom_headers'),
            use_tls=data.get('use_tls', False),
            use_ssl=data.get('use_ssl', False),
            is_default=data.get('is_default', False)
        )
        
        db.session.add(profile)
        db.session.commit()
        
        log_audit(AuditActions.CREATE, f"Created SMTP profile: {profile.name}", 'smtp_profile', profile.id)
        
        return jsonify({'success': True, 'id': profile.id})
    
    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/settings/smtp/update', methods=['POST'])
@login_required
def update_smtp_profile():
    """Update an existing SMTP profile."""
    from utils.models import SMTPProfile, db
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'success': False, 'error': 'No data provided'}), 400
        
        profile_id = data.get('profile_id')
        if not profile_id:
            return jsonify({'success': False, 'error': 'Profile ID is required'}), 400
        
        profile = SMTPProfile.query.get_or_404(profile_id)
        
        # If this is being set as default, unset other defaults
        if data.get('is_default') and not profile.is_default:
            SMTPProfile.query.filter_by(is_default=True).update({'is_default': False})
        
        profile.name = data['name']
        profile.smtp_server = data['smtp_server']
        profile.smtp_port = int(data.get('smtp_port', 25))
        profile.smtp_user = data.get('smtp_user')
        profile.smtp_password = data.get('smtp_password')
        profile.sender_name = data.get('sender_name')
        profile.sender_email = data['sender_email']
        profile.from_name = data.get('from_name')
        profile.reply_to = data.get('reply_to')
        profile.custom_headers = data.get('custom_headers')
        profile.use_tls = data.get('use_tls', False)
        profile.use_ssl = data.get('use_ssl', False)
        profile.is_default = data.get('is_default', False)
        profile.updated_at = datetime.now()
        
        db.session.commit()
        
        log_audit(AuditActions.UPDATE, f"Updated SMTP profile: {profile.name}", 'smtp_profile', profile.id)
        
        return jsonify({'success': True})
    
    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/settings/smtp/<int:profile_id>')
@login_required
def get_smtp_profile(profile_id):
    """Get SMTP profile details."""
    from utils.models import SMTPProfile
    
    profile = SMTPProfile.query.get_or_404(profile_id)
    
    return jsonify({
        'id': profile.id,
        'name': profile.name,
        'smtp_server': profile.smtp_server,
        'smtp_port': profile.smtp_port,
        'smtp_user': profile.smtp_user,
        'smtp_password': profile.smtp_password,
        'sender_name': profile.sender_name,
        'sender_email': profile.sender_email,
        'from_name': profile.from_name,
        'reply_to': profile.reply_to,
        'custom_headers': profile.custom_headers,
        'use_tls': profile.use_tls,
        'use_ssl': profile.use_ssl,
        'is_default': profile.is_default
    })


@app.route('/settings/smtp/<int:profile_id>/delete', methods=['POST'])
@login_required
def delete_smtp_profile(profile_id):
    """Delete an SMTP profile."""
    from utils.models import SMTPProfile, db
    
    try:
        profile = SMTPProfile.query.get_or_404(profile_id)
        
        if profile.is_default:
            return jsonify({'success': False, 'error': 'Cannot delete the default SMTP profile'}), 400
        
        profile_name = profile.name
        
        db.session.delete(profile)
        db.session.commit()
        
        log_audit(AuditActions.DELETE, f"Deleted SMTP profile: {profile_name}", 'smtp_profile', profile_id)
        
        return jsonify({'success': True})
    
    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/settings/smtp/<int:profile_id>/test', methods=['POST'])
@login_required
def test_smtp_profile(profile_id):
    """Test SMTP connection."""
    from utils.models import SMTPProfile
    import smtplib
    from email.mime.text import MIMEText
    
    try:
        profile = SMTPProfile.query.get_or_404(profile_id)
        
        # Test connection
        if profile.use_ssl:
            server = smtplib.SMTP_SSL(profile.smtp_server, profile.smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(profile.smtp_server, profile.smtp_port, timeout=10)
            if profile.use_tls:
                server.starttls()
        
        if profile.smtp_user and profile.smtp_password:
            server.login(profile.smtp_user, profile.smtp_password)
        
        server.quit()
        
        log_audit(AuditActions.VIEW, f"SMTP test successful: {profile.name}", 'smtp_profile', profile.id)
        
        return jsonify({'success': True, 'message': 'Connection successful!'})
        
    except Exception as e:
        log_audit(AuditActions.VIEW, f"SMTP test failed: {profile.name} - {str(e)}", 'smtp_profile', profile.id)
        return jsonify({'success': False, 'error': str(e)}), 400


# =============================================
# Questionnaire Responses API
# =============================================

@app.route('/api/campaign/<int:campaign_id>/questionnaire_responses')
@login_required
def get_questionnaire_responses(campaign_id):
    """Get all questionnaire responses for a campaign"""
    from utils.models import Campaign, Result, Target
    import json as json_module
    
    campaign = Campaign.query.get_or_404(campaign_id)
    
    # Get all results with questionnaire completed
    results = Result.query.filter_by(campaign_id=campaign_id).all()
    
    responses = []
    for r in results:
        # Get target info
        target = Target.query.filter_by(campaign_id=campaign_id, email=r.email).first()
        if not target:
            target = Target.query.filter_by(email=r.email).first()
        
        # Parse answers JSON if available
        answers = None
        if getattr(r, 'questionnaire_answers', None):
            try:
                answers = json_module.loads(r.questionnaire_answers)
            except:
                answers = None
        
        responses.append({
            'email': r.email,
            'first_name': target.first_name if target else '',
            'last_name': target.last_name if target else '',
            'sbu': target.sbu if target else '',
            'clicked': r.clicked,
            'clicked_at': r.clicked_at.isoformat() if r.clicked_at else None,
            'questionnaire_completed': getattr(r, 'questionnaire_completed', False),
            'questionnaire_completed_at': r.questionnaire_completed_at.isoformat() if getattr(r, 'questionnaire_completed_at', None) else None,
            'questionnaire_score': getattr(r, 'questionnaire_score', None),
            'questionnaire_answers': answers,
            'reminder_count': getattr(r, 'reminder_count', 0),
            'last_reminder_sent': r.last_reminder_sent.isoformat() if getattr(r, 'last_reminder_sent', None) else None
        })
    
    # Sort: completed first, then by completion time
    responses.sort(key=lambda x: (not x['questionnaire_completed'], x['questionnaire_completed_at'] or '9999'))
    
    # Calculate summary stats
    total = len(responses)
    clicked = sum(1 for r in responses if r['clicked'])
    completed = sum(1 for r in responses if r['questionnaire_completed'])
    avg_score = 0
    if completed > 0:
        scores = [r['questionnaire_score'] for r in responses if r['questionnaire_score'] is not None]
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
    
    return jsonify({
        'success': True,
        'campaign_name': campaign.name,
        'summary': {
            'total_targets': total,
            'clicked': clicked,
            'completed': completed,
            'click_rate': round(clicked/total*100, 1) if total > 0 else 0,
            'completion_rate': round(completed/clicked*100, 1) if clicked > 0 else 0,
            'average_score': avg_score
        },
        'responses': responses
    })


@app.route('/questionnaire_responses/<int:campaign_id>')
@login_required
def questionnaire_responses_page(campaign_id):
    """Page to view questionnaire responses for a campaign"""
    from utils.models import Campaign
    campaign = Campaign.query.get_or_404(campaign_id)
    return render_template('questionnaire_responses.html', campaign=campaign)


# =============================================
# Reminder Management Pages & API
# =============================================

@app.route('/reminder_settings/<int:campaign_id>')
@login_required
def reminder_settings_page(campaign_id):
    """Page to configure reminder settings for a campaign"""
    from utils.models import Campaign
    campaign = Campaign.query.get_or_404(campaign_id)
    return render_template('reminder_settings.html', campaign=campaign)


@app.route('/api/campaign/<int:campaign_id>/reminder_settings', methods=['GET'])
@login_required
def get_reminder_settings(campaign_id):
    """Get reminder settings for a campaign, falling back to global SystemSetting defaults."""
    from utils.models import Campaign, SystemSetting
    campaign = Campaign.query.get_or_404(campaign_id)

    def _gs(key, fallback=''):
        row = SystemSetting.query.get(key)
        return row.value if (row and row.value is not None) else fallback

    global_interval  = int(_gs('reminder_interval',    '5'))
    global_max       = int(_gs('max_reminders',        '12'))
    global_subject   = _gs('reminder_subject',         '\u26a0\ufe0f REMINDER: Complete Your Security Assessment')
    global_template  = _gs('reminder_email_template',  '')

    return jsonify({
        'success': True,
        'settings': {
            'enabled':          getattr(campaign, 'reminders_enabled', False) or False,
            'interval_minutes': getattr(campaign, 'reminder_interval_minutes', None) or global_interval,
            'max_reminders':    getattr(campaign, 'max_reminders', None)           or global_max,
            'subject':          getattr(campaign, 'reminder_subject', None)         or global_subject,
            'html':             getattr(campaign, 'reminder_html', None)            or global_template,
            'cc':               getattr(campaign, 'reminder_cc', '') or ''
        }
    })


@app.route('/api/campaign/<int:campaign_id>/reminder_settings', methods=['POST'])
@login_required
def update_reminder_settings(campaign_id):
    """Update reminder settings for a campaign"""
    from utils.models import Campaign
    campaign = Campaign.query.get_or_404(campaign_id)
    data = request.get_json()
    
    campaign.reminders_enabled = data.get('enabled', False)
    campaign.reminder_interval_minutes = data.get('interval_minutes', 5)
    campaign.max_reminders = data.get('max_reminders', 12)
    campaign.reminder_subject = data.get('subject', 'Reminder: Complete Your Security Assessment')
    campaign.reminder_html = data.get('html', '')
    campaign.reminder_cc = data.get('cc', '') or None
    
    models_db.session.commit()
    
    log_audit(AuditActions.UPDATE, f"Updated reminder settings for campaign: {campaign.name}", 'campaign', campaign.id)
    
    return jsonify({'success': True, 'message': 'Reminder settings updated'})


@app.route('/api/campaign/<int:campaign_id>/reminder_status')
@login_required
def get_reminder_status(campaign_id):
    """Get current reminder status for a campaign"""
    from utils.models import Campaign, Result
    campaign = Campaign.query.get_or_404(campaign_id)
    
    # Get results for this campaign
    results = Result.query.filter_by(campaign_id=campaign_id).all()
    
    # Count various states
    clicked = sum(1 for r in results if r.clicked)
    completed = sum(1 for r in results if getattr(r, 'questionnaire_completed', False))
    pending = clicked - completed  # Clicked but not completed
    
    # Count reminders sent
    total_reminders_sent = sum(getattr(r, 'reminder_count', 0) or 0 for r in results)
    
    # Users who have reached max reminders
    max_reminders = getattr(campaign, 'max_reminders', 12) or 12
    maxed_out = sum(1 for r in results if r.clicked and not getattr(r, 'questionnaire_completed', False) and (getattr(r, 'reminder_count', 0) or 0) >= max_reminders)
    
    return jsonify({
        'success': True,
        'status': {
            'enabled': getattr(campaign, 'reminders_enabled', False) or False,
            'clicked': clicked,
            'completed': completed,
            'pending': pending,
            'total_reminders_sent': total_reminders_sent,
            'maxed_out': maxed_out,
            'interval_minutes': getattr(campaign, 'reminder_interval_minutes', 5) or 5,
            'max_reminders': max_reminders
        }
    })


@app.route('/api/campaign/<int:campaign_id>/send_reminders', methods=['POST'])
@login_required
def trigger_send_reminders(campaign_id):
    """Manually trigger sending reminders for a campaign"""
    from utils.models import Campaign, Result, SMTPProfile, LandingPage
    
    campaign = Campaign.query.get_or_404(campaign_id)
    
    # Note: We allow manual sending even if automatic reminders are disabled
    # This lets admins manually trigger reminders without enabling the automatic system
    
    # Get SMTP profile
    smtp_profile = SMTPProfile.query.get(campaign.smtp_profile_id) if campaign.smtp_profile_id else None
    if not smtp_profile:
        smtp_profile = SMTPProfile.query.filter_by(is_default=True).first()
    
    if not smtp_profile:
        return jsonify({'success': False, 'error': 'No SMTP profile configured. Please configure an SMTP profile first.'}), 400
    
    # Get landing page for link
    landing_page = LandingPage.query.get(campaign.landing_page_id) if campaign.landing_page_id else None
    if not landing_page:
        return jsonify({'success': False, 'error': 'No landing page configured for this campaign.'}), 400
    
    # Find users who need reminders
    results = Result.query.filter_by(campaign_id=campaign_id, clicked=True).all()
    
    reminder_interval = getattr(campaign, 'reminder_interval_minutes', 5) or 5
    max_reminders = getattr(campaign, 'max_reminders', 12) or 12
    
    sent_count = 0
    skipped_count = 0
    
    for result in results:
        # Skip if questionnaire completed
        if getattr(result, 'questionnaire_completed', False):
            continue
        
        # Skip if max reminders reached
        if (getattr(result, 'reminder_count', 0) or 0) >= max_reminders:
            skipped_count += 1
            continue
        
        # Check if enough time has passed since last reminder
        last_sent = getattr(result, 'last_reminder_sent', None)
        if last_sent:
            time_since_last = (datetime.now() - last_sent).total_seconds() / 60
            if time_since_last < reminder_interval:
                continue
        
        # Send reminder
        try:
            send_reminder_email(result, campaign)
            sent_count += 1
        except Exception as e:
            print(f"Error sending reminder to {result.email}: {e}")
    
    log_audit(AuditActions.UPDATE, f"Triggered reminders for campaign {campaign.name}: {sent_count} sent, {skipped_count} skipped (max reached)", 'campaign', campaign.id)
    
    return jsonify({
        'success': True,
        'message': f'Sent {sent_count} reminders. {skipped_count} users have reached max reminders.'
    })


def send_reminder_email(result, campaign):
    """Send a reminder email to a user who clicked but hasn't completed the questionnaire"""
    import smtplib
    import re
    import logging
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    from datetime import datetime
    from utils.models import SMTPProfile, Target, db
    
    try:
        # Get SMTP profile by ID
        smtp_profile = None
        if campaign.smtp_profile_id:
            smtp_profile = SMTPProfile.query.get(campaign.smtp_profile_id)
        if not smtp_profile:
            smtp_profile = SMTPProfile.query.filter_by(is_default=True).first()
        
        if not smtp_profile:
            logging.error(f"No SMTP profile for campaign {campaign.id}")
            return False
        
        # Get target info
        target = get_target_for_result(result, campaign.id)
        first_name = target.first_name if target else ''
        last_name = target.last_name if target else ''
        
        # Build questionnaire link with token
        # CRITICAL FIX: Ensure we have a valid absolute URL for the background thread
        try:
            from config import get_base_url
            base_url = get_base_url()
        except ImportError:
            # Fallback if config not available
            base_url = "https://192.168.1.100:7443"
            
        # Ensure base_url starts with http/https
        if not base_url.startswith('http'):
            base_url = f"https://{base_url}"
            
        # Construct the full link
        # Use the landing page ID from the campaign
        landing_page_id = campaign.landing_page_id
        # Ensure we use the /submit endpoint which handles the questionnaire logic
        # And include the token which is critical for tracking
        questionnaire_link = f"{base_url}/landing/{landing_page_id}/submit?token={result.token}"
        
        logging.info(f"Generated reminder link: {questionnaire_link}")
        
        # Get reminder template: campaign-level override → global system setting → built-in fallback
        from utils.models import SystemSetting as _SS_t
        _global_tpl_row = _SS_t.query.get('reminder_email_template')
        _global_tpl = _global_tpl_row.value if (_global_tpl_row and _global_tpl_row.value) else ''

        _builtin_fallback = '''<!DOCTYPE html>
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
            <p>Our security systems have detected that you <strong>clicked</strong> on a known phishing link.</p>
            <div class="reminder-note">
                <span class="red-text">Reminder: You will be prompted every 5 minutes until this security assessment is completed.</span>
            </div>
            <p style="text-align: center; margin: 30px 0;">
                <a href="{{questionnaire_link}}" class="button">Complete Security Assessment Now</a>
            </p>
        </div>
        <div class="footer">
            <p>Automated security notification | Contact your system administrator with questions</p>
        </div>
    </div>
</body>
</html>'''

        template = getattr(campaign, 'reminder_html', '') or _global_tpl or _builtin_fallback
        
        # Build tracking pixel URL for open tracking
        tracking_pixel_url = f"{base_url}/pixel?token={result.token}"
        tracking_pixel_html = f'<img src="{tracking_pixel_url}" width="1" height="1" style="display:none; border:0;" alt="" />'
        
        # Replace variables (handle both spellings and spaces)
        html_body = template.replace('{{FirstName}}', first_name)
        html_body = html_body.replace('{{LastName}}', last_name)
        html_body = html_body.replace('{{email}}', result.email)
        
        # Add tracking pixel - replace placeholder or inject before </body>
        html_body = html_body.replace('{{tracking_pixel}}', tracking_pixel_html)
        if '</body>' in html_body and '{{tracking_pixel}}' not in template:
            html_body = html_body.replace('</body>', f'{tracking_pixel_html}</body>')
        
        # Handle all link placeholder variants:
        #  {landing_page_url}      — used by new system-settings template
        #  {{questionnaire_link}}  — used by legacy per-campaign templates
        html_body = html_body.replace('{landing_page_url}', questionnaire_link)
        html_body = html_body.replace('{{questionnaire_link}}', questionnaire_link)
        html_body = html_body.replace('{{ questionnaire_link }}', questionnaire_link)
        html_body = html_body.replace('{{questionaire_link}}', questionnaire_link)   # typo variant
        html_body = html_body.replace('{{ questionaire_link }}', questionnaire_link)
        
        html_body = html_body.replace('{{campaign_name}}', campaign.name)
        
        # Catch any remaining empty or un-replaced href values
        html_body = re.sub(r'href=["\']\s*["\']', f'href="{questionnaire_link}"', html_body)
        html_body = re.sub(r'href=["\']\{[^"\']*\}["\']', f'href="{questionnaire_link}"', html_body)
        
        # Get subject — campaign override or global system default
        from utils.models import SystemSetting as _SS
        def _gss(key, fb=''):
            row = _SS.query.get(key)
            return row.value if (row and row.value is not None) else fb

        subject = (campaign.reminder_subject
                   or _gss('reminder_subject', '⚠️ REMINDER: Complete Your Security Assessment'))

        # Always use the dedicated reminder sender — never the campaign sender
        reminder_sender_email = _gss('reminder_sender_email', '')
        reminder_sender_name  = _gss('reminder_sender_name',  'Information Security')

        if not reminder_sender_email:
            logging.error("reminder_sender_email not configured in System Settings — reminder not sent.")
            return False

        # Use the reminder-specific SMTP profile if configured, otherwise fall back to campaign/default
        reminder_profile_id = _gss('reminder_smtp_profile_id', '')
        if reminder_profile_id:
            rp = SMTPProfile.query.get(int(reminder_profile_id))
            if rp:
                smtp_profile = rp

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"{reminder_sender_name} <{reminder_sender_email}>"
        msg['To'] = result.email
        
        # Add CC if configured
        if campaign.reminder_cc:
            msg['Cc'] = campaign.reminder_cc
            recipients = [result.email, campaign.reminder_cc]
        else:
            recipients = [result.email]
        
        msg.attach(MIMEText(html_body, 'html'))
        
        # Connect and send
        if smtp_profile.use_ssl:
            server = smtplib.SMTP_SSL(smtp_profile.smtp_server, smtp_profile.smtp_port)
        else:
            server = smtplib.SMTP(smtp_profile.smtp_server, smtp_profile.smtp_port)
            if smtp_profile.use_tls:
                server.starttls()
        
        if smtp_profile.smtp_user and smtp_profile.smtp_password:
            server.login(smtp_profile.smtp_user, smtp_profile.smtp_password)
        
        server.sendmail(reminder_sender_email, recipients, msg.as_string())
        server.quit()
        
        # Update reminder tracking
        result.last_reminder_sent = datetime.now()
        result.reminder_count = (result.reminder_count or 0) + 1
        db.session.commit()
        
        logging.info(f"Sent reminder #{result.reminder_count} to {result.email} for campaign {campaign.id}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send reminder to {result.email}: {e}")
        return False
    

@app.route('/api/historical_data/analyze_csv', methods=['POST'])
@app.route('/api/historical_data/analyze_csv', methods=['POST'])
@login_required
def analyze_historical_csv():
    """Analyze uploaded CSV data and aggregate by SBU, looking up missing SBUs from DB."""
    from utils.models import Target
    
    data = request.get_json()
    rows = data.get('rows', [])
    
    if not rows:
        return jsonify({'success': False, 'error': 'No data provided'})
    
    stats = {}
    
    for row in rows:
        email = row.get('email', '').strip().lower()
        sbu = row.get('sbu', '').strip()
        clicked = row.get('clicked', False)
        reported = row.get('reported', False)
        
        # If SBU is missing, try to find it in the database
        if not sbu and email:
            # Try to find target by email that has an SBU (most recent first)
            target = Target.query.filter_by(email=email)\
                .filter(Target.sbu != None, Target.sbu != '')\
                .order_by(Target.id.desc()).first()
            
            if target:
                sbu = target.sbu
        
        # Default to Unknown if still missing
        if not sbu:
            sbu = 'Unknown'
            
        # Initialize stats for this SBU if needed
        if sbu not in stats:
            stats[sbu] = {'targeted': 0, 'clicked': 0, 'reported': 0}
            
        stats[sbu]['targeted'] += 1
        if clicked:
            stats[sbu]['clicked'] += 1
        if reported:
            stats[sbu]['reported'] += 1
            
            
    return jsonify({'success': True, 'stats': stats})


def init_resume_campaigns():
    """Resume any running campaigns on startup."""
    with app.app_context():
        try:
            from utils.models import Campaign, Target, Result, db
            from utils.email_sender import send_campaign_emails_async
            
            running_campaigns = Campaign.query.filter_by(status='running').all()
            for campaign in running_campaigns:
                app.logger.info(f"Resuming campaign {campaign.id} ({campaign.name})")
                targets = Target.query.filter_by(campaign_id=campaign.id).all()
                results = Result.query.filter_by(campaign_id=campaign.id).all()
                
                # Emails already sent
                sent_emails = set(r.email for r in results if r.sent)
                
                # Emails pending
                pending_emails = [t.email for t in targets if t.email not in sent_emails]
                
                if pending_emails:
                    app.logger.info(f"Campaign {campaign.id} has {len(pending_emails)} pending emails. Launching background task...")
                    send_campaign_emails_async(pending_emails, campaign_id=campaign.id)
                else:
                    app.logger.info(f"Campaign {campaign.id} has no pending emails. Marking as finished.")
                    campaign.status = 'finished'
                    if not campaign.finished_at:
                        campaign.finished_at = datetime.now()
                    db.session.commit()
        except Exception as e:
            app.logger.error(f"Error resuming campaigns: {e}")

# Run automatic campaign resume
try:
    init_resume_campaigns()
except Exception as e:
    print(f"Error initializing campaign resume: {e}")
