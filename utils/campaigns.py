from flask import Blueprint, jsonify, request, render_template, session, redirect, url_for
from functools import wraps
from pathlib import Path
from datetime import datetime
import logging

from .email_sender import send_campaign_emails_async, get_job_status, JOBS, JOBS_LOCK
from .models import db, Campaign, Target, Result, SMTPProfile, SystemSetting
import sendemails

def reset_past_target_flags():
    """Set past_target=False for all targets (new year reset)."""
    updated = Target.query.filter_by(past_target=True).update({Target.past_target: False})
    db.session.commit()
    return updated
campaigns_bp = Blueprint('campaigns', __name__, url_prefix='/campaigns')

logger = logging.getLogger(__name__)


def login_required(f):
    """Decorator to require login for routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function


@campaigns_bp.route('/', methods=['GET'])
@login_required
def list_campaigns():
    """Campaign list page showing all campaigns."""
    campaigns = Campaign.query.order_by(Campaign.created_at.desc()).all()
    return render_template('campaigns_list.html', campaigns=campaigns)


@campaigns_bp.route('/launch_test', methods=['GET'])
@login_required
def launch_test_campaign():
    """Start a background test send using the project's EMAILS_FILE (if present in sendemails).

    Returns job_id which can be polled via /campaigns/status/<job_id>.
    """
    # Try to locate the default EMAILS_FILE from sendemails module if available
    try:
        import sendemails
        email_file = getattr(sendemails, 'EMAILS_FILE', None)
    except Exception:
        email_file = None

    if email_file:
        path = Path(email_file)
        if not path.exists():
            return jsonify({"error": "EMAILS_FILE not found", "path": str(path)}), 404
    else:
        path = Path('emails.txt')
        if not path.exists():
            return jsonify({"error": "No email source configured (no sendemails.EMAILS_FILE and emails.txt missing)"}), 400

    # Read addresses and start async job
    with path.open('r', encoding='utf-8') as fh:
        emails = [line.strip() for line in fh if line.strip()]

    job_id = send_campaign_emails_async(emails)
    return jsonify({"job_id": job_id})


@campaigns_bp.route('/launch', methods=['POST'])
@login_required
def launch_campaign():
    """Start a background send for provided emails (JSON body: {"emails": [..]}).

    Returns job_id for status polling.
    """
    data = request.get_json(silent=True) or {}
    emails = data.get('emails')
    if not emails or not isinstance(emails, list):
        return jsonify({"error": "Provide JSON body with 'emails': [..]"}), 400

    job_id = send_campaign_emails_async(emails)
    return jsonify({"job_id": job_id})


@campaigns_bp.route('/status/<job_id>', methods=['GET'])
@login_required
def campaign_status(job_id):
    status = get_job_status(job_id)
    if status is None:
        return jsonify({"error": "Unknown job id"}), 404
    return jsonify(status)


@campaigns_bp.route('/stop/<job_id>', methods=['POST'])
@login_required
def stop_campaign(job_id):
    """Request cancellation of a running campaign job and mark campaign stopped."""
    try:
        with JOBS_LOCK:
            job = JOBS.get(job_id)
            if not job:
                return jsonify({'success': False, 'message': 'Job not found'}), 404
            job['state'] = 'cancelled'

        # Also try to find the campaign and set its status
        campaign = Campaign.query.filter_by(job_id=job_id).first()
        if campaign:
            campaign.status = 'stopped'
            db.session.commit()

        return jsonify({'success': True, 'message': 'Stop requested'})
    except Exception as e:
        logger.exception(f"Error requesting stop for job {job_id}: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@campaigns_bp.route('/send_test_email', methods=['POST'])
@login_required
def send_test_email():
    """Send a test email with the current template for preview purposes."""
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.image import MIMEImage
    from email.mime.base import MIMEBase
    from email import encoders
    from .models import TemplateImage, TemplateAttachment
    
    try:
        # Get system defaults
        default_sender_name = 'IT Security'
        default_sender_email = 'security@company.com'
        
        try:
            s_name = SystemSetting.query.get('sender_name')
            s_email = SystemSetting.query.get('sender_email')
            if s_name: default_sender_name = s_name.value
            if s_email: default_sender_email = s_email.value
        except Exception:
            pass

        data = request.get_json()
        to_email = data.get('to_email', '').strip()
        subject = data.get('subject', 'Test Email')
        template_html = data.get('template_html', '')
        sender_name = data.get('sender_name', default_sender_name)
        sender_email = data.get('sender_email', default_sender_email)
        smtp_profile_id = data.get('smtp_profile_id')
        template_id = data.get('template_id')
        
        if not to_email:
            return jsonify({'success': False, 'error': 'No recipient email provided'})
        
        if not template_html:
            return jsonify({'success': False, 'error': 'No template content provided'})
        
        # Replace template variables with sample data
        # Get base URL for tracking pixel
        try:
            from config import TRACKING_BASE_URL
            base_url = TRACKING_BASE_URL
        except ImportError:
            base_url = 'https://localhost:7443'

        html_content = template_html
        html_content = html_content.replace('{{FirstName}}', 'John')
        html_content = html_content.replace('{{LastName}}', 'Doe')
        html_content = html_content.replace('{{Email}}', to_email)
        html_content = html_content.replace('{{link}}', '#test-link-disabled')
        
        # Use a real pixel URL for testing connectivity
        pixel_url = f"{base_url}/pixel?token=TEST-TOKEN-{to_email}"
        html_content = html_content.replace('{{tracking_pixel}}', f'<img src="{pixel_url}" width="1" height="1" style="border:0;margin:0;padding:0;" alt="" />')
        
        # Also handle variations without braces (in case of encoding issues)
        html_content = html_content.replace('{ {FirstName} }', 'John')
        html_content = html_content.replace('{ {LastName} }', 'Doe')
        
        # Check if using specific SMTP profile
        smtp_profile = None
        if smtp_profile_id:
            smtp_profile = SMTPProfile.query.get(int(smtp_profile_id))
        
        # If no profile selected, try to find default
        if not smtp_profile:
            smtp_profile = SMTPProfile.query.filter_by(is_default=True).first()
            
        if smtp_profile:
            # Send using the specific SMTP profile
            try:
                msg = MIMEMultipart('related')
                msg['Subject'] = f"[TEST] {subject}"
                from_addr = smtp_profile.sender_email
                from_name = smtp_profile.sender_name or sender_name
                msg['From'] = f"{from_name} <{from_addr}>"
                msg['To'] = to_email
                msg.attach(MIMEText(html_content, 'html'))
                
                # Attach CID images and file attachments if template_id is provided
                if template_id:
                    try:
                        db_images = TemplateImage.query.filter_by(template_id=int(template_id)).all()
                        for img in db_images:
                            mime_subtype = img.mime_type.split('/')[-1].lower()
                            if mime_subtype == 'jpg':
                                mime_subtype = 'jpeg'
                            part = MIMEImage(bytes(img.data), mime_subtype)
                            cid_bare = img.cid
                            part.add_header('Content-ID', f'<{cid_bare}>')
                            part.add_header('Content-Disposition', 'inline', filename=img.filename)
                            part.set_param('name', img.filename)
                            msg.attach(part)
                        
                        db_atts = TemplateAttachment.query.filter_by(template_id=int(template_id)).all()
                        for att in db_atts:
                            main_t, sub_t = att.mime_type.split('/', 1) if '/' in att.mime_type else ('application', 'octet-stream')
                            part = MIMEBase(main_t, sub_t)
                            part.set_payload(bytes(att.data))
                            encoders.encode_base64(part)
                            part.add_header('Content-Disposition', 'attachment', filename=att.filename)
                            msg.attach(part)
                            
                        logger.info(f"Test email attached {len(db_images)} CID images and {len(db_atts)} files")
                    except Exception as e:
                        logger.warning(f"Failed to attach files in test email: {e}")

                if smtp_profile.use_ssl and smtp_profile.smtp_port == 465:
                    # SSL connection
                    import ssl
                    context = ssl.create_default_context()
                    with smtplib.SMTP_SSL(smtp_profile.smtp_server, smtp_profile.smtp_port, context=context) as server:
                        if smtp_profile.smtp_user and smtp_profile.smtp_password:
                            server.login(smtp_profile.smtp_user, smtp_profile.smtp_password)
                        server.send_message(msg)
                else:
                    # Regular or STARTTLS connection
                    with smtplib.SMTP(smtp_profile.smtp_server, smtp_profile.smtp_port) as server:
                        if smtp_profile.use_tls:
                            server.starttls()
                        if smtp_profile.smtp_user and smtp_profile.smtp_password:
                            server.login(smtp_profile.smtp_user, smtp_profile.smtp_password)
                        server.send_message(msg)
                
                logger.info(f"Test email sent successfully to {to_email} using SMTP profile: {smtp_profile.name}")
                return jsonify({'success': True})
            except Exception as e:
                logger.exception(f"Error sending test email via SMTP profile {smtp_profile.name}: {e}")
                return jsonify({'success': False, 'error': f'SMTP Error: {str(e)}'})
        
        # Fallback to legacy sendemails module if no profile found
        success = sendemails.send_email(to_email, f"[TEST] {subject}", html_content)
        
        if success:
            logger.info(f"Test email sent successfully to {to_email}")
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'Failed to send email. Check server logs.'})
            
    except Exception as e:
        logger.exception(f"Error sending test email: {e}")
        return jsonify({'success': False, 'error': str(e)})


# --------- UI routes for campaign creation flow ---------
@campaigns_bp.route('/create', methods=['GET'])
@login_required
def create_campaign_step1():
    """Render step 1 (campaign details)."""
    smtp_profiles = SMTPProfile.query.all()
    return render_template('campaign_create_step1.html', smtp_profiles=smtp_profiles)


@campaigns_bp.route('/create_step1', methods=['POST'])
@login_required
def create_campaign_step1_post():
    # Collect basic campaign info and store it in session
    name = request.form.get('campaign-name', '').strip()
    description = request.form.get('campaign-description', '').strip()
    campaign_type = request.form.get('campaign-type', 'credential_harvest').strip()
    sender_name = request.form.get('sender-name', '').strip()
    sender_email = request.form.get('sender-email', '').strip()
    start_date = request.form.get('start-date')
    smtp_profile_id = request.form.get('smtp-profile')

    # Create Campaign record in DB
    campaign = Campaign(
        name=name or 'Untitled Campaign', 
        description=description, 
        status='draft',
        campaign_type=campaign_type,
        sender_name=sender_name,
        sender_email=sender_email,
        smtp_profile_id=int(smtp_profile_id) if smtp_profile_id else None
    )
    # If a scheduled start date was provided, try to parse and store it
    if start_date:
        try:
            campaign.scheduled_for = datetime.fromisoformat(start_date)
        except Exception:
            logger.warning(f"Could not parse start-date '{start_date}' for campaign")

    db.session.add(campaign)
    db.session.commit()
    session['campaign_id'] = campaign.id
    return redirect(url_for('campaigns.create_campaign_step2'))


@campaigns_bp.route('/create_step2', methods=['GET', 'POST'])
@login_required
def create_campaign_step2():
    """Template design step: GET shows form, POST saves subject/template and continues to targets."""
    if request.method == 'POST':
        subject = request.form.get('subject', '').strip()
        template_html = request.form.get('template_html', '').strip()
        template_id = request.form.get('template_id')
        landing_page_id = request.form.get('landing_page_id')
        smtp_profile_id = request.form.get('smtp_profile_id')
        sender_name = request.form.get('sender_name', '').strip()
        sender_email = request.form.get('sender_email', '').strip()
        
        campaign_id = session.get('campaign_id')
        if campaign_id:
            campaign = Campaign.query.get(campaign_id)
            if campaign:
                campaign.subject = subject
                campaign.template_html = template_html
                campaign.template_id = int(template_id) if template_id else None
                campaign.landing_page_id = int(landing_page_id) if landing_page_id else None
                campaign.smtp_profile_id = int(smtp_profile_id) if smtp_profile_id else None
                campaign.sender_name = sender_name
                campaign.sender_email = sender_email
                db.session.commit()
        return redirect(url_for('campaigns.create_campaign_targets'))

    # Load templates, landing pages, and SMTP profiles for selectors
    from .models import EmailTemplate, LandingPage, SMTPProfile
    templates = EmailTemplate.query.order_by(EmailTemplate.name).all()
    landing_pages = LandingPage.query.order_by(LandingPage.name).all()
    smtp_profiles = SMTPProfile.query.order_by(SMTPProfile.is_default.desc(), SMTPProfile.name).all()
    
    # Provide some context variables for preview
    campaign_id = session.get('campaign_id')
    campaign = None
    if campaign_id:
        campaign = Campaign.query.get(campaign_id)
    
    return render_template('campaign_create_step2.html', 
                          sender_name='IT Security', 
                          recipient_name='User', 
                          company_name='ACME Corp', 
                          link='http://example.com', 
                          campaign=campaign,
                          templates=templates,
                          landing_pages=landing_pages,
                          smtp_profiles=smtp_profiles)


@campaigns_bp.route('/targets', methods=['GET', 'POST'])
@login_required
def create_campaign_targets():
    """Target selection page. POSTing structured target data with FirstName, LastName, Email, SBU."""
    # Check if we have a valid campaign in session
    campaign_id = session.get('campaign_id')
    if not campaign_id:
        # No campaign in session - redirect to step 1
        return redirect(url_for('campaigns.create_campaign_step1'))
    
    # Verify the campaign exists
    campaign = Campaign.query.get(campaign_id)
    if not campaign:
        # Campaign doesn't exist - clear session and redirect
        session.pop('campaign_id', None)
        return redirect(url_for('campaigns.create_campaign_step1'))
    
    if request.method == 'POST':
        # Try to get structured JSON data first
        targets_data_str = request.form.get('targets_data', '')
        
        if targets_data_str:
            # Parse JSON data
            import json
            try:
                targets_data = json.loads(targets_data_str)
            except Exception:
                targets_data = []
        else:
            # Fallback to simple email list
            emails_text = request.form.get('emails', '')
            emails = [e.strip() for e in emails_text.splitlines() if e.strip()]
            targets_data = [{'email': e, 'firstName': '', 'lastName': '', 'sbu': 'Default'} for e in emails]
        
        if not targets_data:
            return render_template('targets.html', error='No valid targets provided')

        # Create Target rows - campaign_id already validated at function start
        emails = []
        for t_data in targets_data:
            email = t_data.get('email', '')
            if not email:
                continue
            
            first_name = t_data.get('firstName', '')
            last_name = t_data.get('lastName', '')
            
            # If no names provided, try to extract from email
            if not first_name:
                first_name, _ = sendemails.extract_names_from_email(email)
            
            t = Target(
                campaign_id=campaign_id,
                email=email,
                first_name=first_name,
                last_name=last_name,
                sbu=t_data.get('sbu'),
                position=t_data.get('position')
            )
            db.session.add(t)
            emails.append(email)
        
        db.session.commit()

        # Start background job and attach job_id to campaign
        job_id = send_campaign_emails_async(emails, campaign_id=campaign_id)
        # Refresh campaign object after commit
        campaign = Campaign.query.get(campaign_id)
        campaign.job_id = job_id
        campaign.status = 'running'
        db.session.commit()

        return redirect(url_for('campaigns.campaign_status_page', job_id=job_id))

    return render_template('targets.html')


@campaigns_bp.route('/status_page/<job_id>', methods=['GET'])
@login_required
def campaign_status_page(job_id):
    """Render campaign status page that polls the status endpoint."""
    # Try to find a campaign by job_id
    campaign = Campaign.query.filter_by(job_id=job_id).first()
    
    # Fetch results for this campaign
    results_data = []
    if campaign:
        results = db.session.query(Result, Target).outerjoin(
            Target, 
            (Target.campaign_id == Result.campaign_id) & (Target.email == Result.email)
        ).filter(Result.campaign_id == campaign.id).all()
        
        for r, t in results:
            results_data.append({
                'id': r.id,
                'email': r.email,
                'first_name': t.first_name if t else '',
                'last_name': t.last_name if t else '',
                'sbu': t.sbu if t else '',
                'token': r.token,
                'status': r.status,
                'error': r.error,
                'opened': r.opened,
                'clicked': r.clicked,
                'reported': getattr(r, 'reported', False),
                'compromised': getattr(r, 'compromised', False),
                'sent_at': r.sent_at.strftime('%Y-%m-%d %H:%M:%S') if r.sent_at else None,
                'opened_at': r.opened_at.strftime('%Y-%m-%d %H:%M:%S') if r.opened_at else None,
                'clicked_at': r.clicked_at.strftime('%Y-%m-%d %H:%M:%S') if r.clicked_at else None,
                'submitted_at': r.submitted_at.strftime('%Y-%m-%d %H:%M:%S') if getattr(r, 'submitted_at', None) else None,
                'questionnaire_completed': getattr(r, 'questionnaire_completed', False),
                'questionnaire_completed_at': r.questionnaire_completed_at.strftime('%Y-%m-%d %H:%M:%S') if getattr(r, 'questionnaire_completed_at', None) else None,
                'questionnaire_score': getattr(r, 'questionnaire_score', None),
                'questionnaire_answers': getattr(r, 'questionnaire_answers', None),
                'last_reminder_sent': r.last_reminder_sent.strftime('%Y-%m-%d %H:%M:%S') if getattr(r, 'last_reminder_sent', None) else None,
                'reminder_count': getattr(r, 'reminder_count', 0) or 0,
            })
    
    return render_template('campaign_status.html', job_id=job_id, campaign=campaign, results=results_data)


@campaigns_bp.route('/results_json/<int:campaign_id>', methods=['GET'])
@login_required
def get_campaign_results_json(campaign_id):
    """Get campaign results as JSON for live polling."""
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'success': False, 'error': 'Campaign not found'}), 404
        
        results = Result.query.filter_by(campaign_id=campaign_id).all()
        results_data = []
        
        for r in results:
            # First try to find campaign-specific target, then fall back to global target
            t = Target.query.filter_by(campaign_id=campaign_id, email=r.email).first()
            if not t:
                t = Target.query.filter_by(campaign_id=None, email=r.email).first()
            results_data.append({
                'id': r.id,
                'email': r.email,
                'first_name': t.first_name if t else '',
                'last_name': t.last_name if t else '',
                'sbu': t.sbu if t else '',
                'opened': r.opened,
                'clicked': r.clicked,
                'reported': getattr(r, 'reported', False),
                'compromised': getattr(r, 'compromised', False),
                'questionnaire_completed': getattr(r, 'questionnaire_completed', False),
                'questionnaire_score': getattr(r, 'questionnaire_score', None),
                'reminder_count': getattr(r, 'reminder_count', 0) or 0,
                'opened_at': r.opened_at.isoformat() if r.opened_at else None,
                'clicked_at': r.clicked_at.isoformat() if r.clicked_at else None,
            })
        
        return jsonify({
            'success': True,
            'results': results_data,
            'campaign_status': campaign.status
        })
    except Exception as e:
        logger.error(f"Error fetching results JSON for campaign {campaign_id}: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@campaigns_bp.route('/delete/<int:campaign_id>', methods=['POST'])
@login_required
def delete_campaign(campaign_id):
    """Delete a campaign and all associated results and targets."""
    try:
        campaign = Campaign.query.get(campaign_id)
        if not campaign:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404
        
        # Delete associated results
        Result.query.filter_by(campaign_id=campaign_id).delete()
        
        # Delete campaign-specific targets (not global ones)
        Target.query.filter_by(campaign_id=campaign_id).delete()
        
        # Delete the campaign
        db.session.delete(campaign)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Campaign deleted successfully'})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting campaign {campaign_id}: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@campaigns_bp.route('/clone/<int:campaign_id>', methods=['POST'])
@login_required
def clone_campaign(campaign_id):
    """Clone a campaign with its template and settings."""
    try:
        original = Campaign.query.get(campaign_id)
        if not original:
            return jsonify({'success': False, 'message': 'Campaign not found'}), 404
        
        # Create a new campaign with the same settings
        cloned = Campaign(
            name=f"{original.name} (Copy)",
            description=original.description,
            subject=original.subject,
            template_html=original.template_html,
            status='draft',
            campaign_type=getattr(original, 'campaign_type', None),
            sender_name=getattr(original, 'sender_name', None),
            sender_email=getattr(original, 'sender_email', None)
        )
        db.session.add(cloned)
        db.session.commit()
        
        # Store in session for the creation flow
        session['campaign_id'] = cloned.id
        
        return jsonify({'success': True, 'message': 'Campaign cloned successfully', 'id': cloned.id})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error cloning campaign {campaign_id}: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500


@campaigns_bp.route('/<int:campaign_id>/results', methods=['GET'])
@login_required
def campaign_results(campaign_id):
    """Campaign results page - renders HTML template with results data."""
    from .models import Campaign
    
    campaign = Campaign.query.get_or_404(campaign_id)
    
    # Join Result and Target to get full details
    results = db.session.query(Result, Target).outerjoin(
        Target, 
        (Target.campaign_id == Result.campaign_id) & (Target.email == Result.email)
    ).filter(Result.campaign_id == campaign_id).all()
    
    results_data = []
    for r, t in results:
        results_data.append({
            'id': r.id,
            'email': r.email,
            'first_name': t.first_name if t else '',
            'last_name': t.last_name if t else '',
            'sbu': t.sbu if t else '',
            'token': r.token,
            'status': r.status,
            'error': r.error,
            'opened': r.opened,
            'clicked': r.clicked,
            'reported': getattr(r, 'reported', False),
            'compromised': getattr(r, 'compromised', False),
            'sent_at': r.sent_at.strftime('%Y-%m-%d %H:%M:%S') if r.sent_at else None,
            'opened_at': r.opened_at.strftime('%Y-%m-%d %H:%M:%S') if r.opened_at else None,
            'clicked_at': r.clicked_at.strftime('%Y-%m-%d %H:%M:%S') if r.clicked_at else None,
            'submitted_at': r.submitted_at.strftime('%Y-%m-%d %H:%M:%S') if getattr(r, 'submitted_at', None) else None,
            'questionnaire_completed': getattr(r, 'questionnaire_completed', False),
            'questionnaire_completed_at': r.questionnaire_completed_at.strftime('%Y-%m-%d %H:%M:%S') if getattr(r, 'questionnaire_completed_at', None) else None,
            'questionnaire_score': getattr(r, 'questionnaire_score', None),
            'last_reminder_sent': r.last_reminder_sent.strftime('%Y-%m-%d %H:%M:%S') if getattr(r, 'last_reminder_sent', None) else None,
            'reminder_count': getattr(r, 'reminder_count', 0) or 0,
        })
    
    return render_template('campaign_status.html', campaign=campaign, results=results_data)


@campaigns_bp.route('/check_history', methods=['POST'])
@login_required
def check_target_history():
    """Check which campaigns the provided emails have participated in."""
    data = request.get_json()
    emails = data.get('emails', [])
    
    if not emails:
        return jsonify({})
    
    # Find all targets matching these emails
    targets = Target.query.filter(Target.email.in_(emails)).all()
    
    # Group by email and collect campaign names
    history = {}
    for target in targets:
        email = target.email
        if email not in history:
            history[email] = []
        
        campaign = Campaign.query.get(target.campaign_id)
        if campaign:
            history[email].append(campaign.name)
    
    return jsonify(history)
