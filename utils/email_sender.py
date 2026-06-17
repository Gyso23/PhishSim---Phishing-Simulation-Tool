"""Wrapper around the project's `sendemails.py` to provide a small, tested API
for triggering sends from the web app.

Functions:
- send_campaign_emails(email_addresses): generate links and send using sendemails module.
- send_from_file(path): read emails from a file and call send_campaign_emails.
"""
import logging
import threading
from flask import current_app
import uuid
from typing import Iterable, Tuple, Dict, Optional
from pathlib import Path
import time
from datetime import datetime

from .metrics import log_metric

logger = logging.getLogger(__name__)

try:
    import sendemails
except Exception:
    sendemails = None

# Simple in-memory job store for background sends (job_id -> status dict)
# status dict contains: state: pending|running|done|failed, sent, failed, started_at, finished_at, details
JOBS: Dict[str, Dict] = {}
JOBS_LOCK = threading.Lock()


def _generate_landing_page_links(email_addresses: list, landing_page_id: int, campaign_id: int) -> Tuple[Dict[str, Tuple[str, str]], Dict[str, str]]:
    """Generate landing page links instead of generic tracking URLs.
    
    Returns:
        Tuple of (email_links, token_map)
        - email_links: {email: (click_link, pixel_url)}
        - token_map: {token: email}
    """
    try:
        # Get base URL from config
        try:
            from config import TRACKING_BASE_URL
            base_url = TRACKING_BASE_URL
        except ImportError:
            if sendemails:
                base_url = getattr(sendemails, 'TRACKING_BASE_URL', 'https://localhost:7443')
            else:
                base_url = 'https://localhost:7443'
        
        links = {}
        token_map = {}
        
        for email in email_addresses:
            clean_email = email.replace('\ufeff', '')
            token = str(uuid.uuid4())
            
            # Generate landing page URL with email and campaign_id
            landing_url = f"{base_url}/landing/{landing_page_id}/submit?email={clean_email}&campaign_id={campaign_id}&token={token}"
            pixel_url = f"{base_url}/pixel?token={token}"
            # Tracked logo URL - serves actual image while tracking opens
            logo_url = f"{base_url}/track-image/logo.png?token={token}"
            
            links[clean_email] = (landing_url, pixel_url, token, logo_url)
            token_map[token] = clean_email
        
        return links, token_map
        
    except Exception as e:
        logger.error(f"Error generating landing page links: {e}")
        # Fallback to standard links if error
        if sendemails:
            return sendemails.generate_unique_links(email_addresses)
        return {}, {}


def _run_send_job(job_id: str, emails: Iterable[str], campaign_id: Optional[int], app, stagger_delay_seconds: int = 0):
    with JOBS_LOCK:
        JOBS[job_id]['state'] = 'running'
        JOBS[job_id]['started_at'] = time.time()

    try:
        emails_list = [e.strip() for e in emails if e and e.strip()]

        if not sendemails:
            raise RuntimeError('sendemails.py not available')

        # Get campaign template and landing page if campaign_id provided
        template_html = None
        subject = None
        landing_page_id = None
        if campaign_id and app:
            try:
                with app.app_context():
                    from .models import Campaign
                    campaign = Campaign.query.get(campaign_id)
                    if campaign:
                        template_html = campaign.template_html
                        subject = campaign.subject
                        landing_page_id = campaign.landing_page_id
            except Exception as e:
                logger.warning(f'Could not fetch campaign template: {e}')

        # Generate unique tokens for each email
        # If landing_page_id is set, use landing page URLs instead of generic tracking
        if landing_page_id:
            email_links, token_map = _generate_landing_page_links(emails_list, landing_page_id, campaign_id)
        else:
            email_links, token_map = sendemails.generate_unique_links(emails_list)

        # Send emails with personalized content (cooperative cancelable send)
        result = _send_personalized_emails(
            job_id,
            emails_list,
            email_links,
            template_html=template_html,
            subject=subject,
            campaign_id=campaign_id,
            app=app,
            stagger_delay_seconds=stagger_delay_seconds
        )

        sent = failed = 0
        details = {}
        cancelled = False
        if isinstance(result, dict):
            # new dict format with keys: sent, failed, details, cancelled
            sent = result.get('sent', 0)
            failed = result.get('failed', 0)
            details = result.get('details', {})
            cancelled = result.get('cancelled', False)
        elif isinstance(result, tuple) and len(result) == 3:
            sent, failed, details = result
        elif isinstance(result, tuple) and len(result) == 2:
            sent, failed = result
        else:
            sent = len(email_links)
            failed = max(0, len(emails_list) - sent)

        # Persist token mapping if possible and write DB Results when campaign_id provided
        try:
            token_file = getattr(sendemails, 'TOKEN_MAPPING_FILE', None)
            if token_file and token_map:
                p = Path(token_file)
                with p.open('a', encoding='utf-8') as fh:
                    for token, email in token_map.items():
                        fh.write(f"{token}:{email}\n")
        except Exception:
            logger.exception('Failed to persist token mapping')

        # If a campaign_id was provided, persist results to the database
        if campaign_id is not None and app is not None:
            try:
                with app.app_context():
                    from .models import db, Campaign, Result, Target
                    logger.info(f"Persisting results for campaign {campaign_id}: {len(details)} emails, token_map has {len(token_map)} entries")
                    # Update campaign counters and write individual results
                    sent_emails = []
                    for email, info in details.items():
                        status = info.get('status', '')
                        error_msg = info.get('error', '')
                        token = None
                        # find token by reverse lookup in token_map
                        for t, em in token_map.items():
                            if em == email:
                                token = t
                                break
                        logger.info(f"Creating result for {email}: token={token}, status={status}")
                        r = Result(
                            campaign_id=campaign_id, 
                            email=email, 
                            token=token, 
                            status=status, 
                            error=error_msg,
                            sent=(status == 'sent'),
                            sent_at=datetime.now() if status == 'sent' else None
                        )
                        db.session.add(r)
                        if status == 'sent':
                            sent_emails.append(email)
                    
                    # Mark targets as past_target=True for all emails that were sent
                    if sent_emails:
                        Target.query.filter(Target.email.in_(sent_emails)).update(
                            {Target.past_target: True}, synchronize_session=False
                        )
                    
                    # update campaign summary
                    campaign = Campaign.query.get(campaign_id)
                    if campaign:
                        campaign.sent_count = sent
                        campaign.failed_count = failed
                        campaign.job_id = job_id
                        if campaign.status != 'running':
                            campaign.status = 'running'
                        db.session.commit()
            except Exception:
                logger.exception('Failed to persist campaign results to DB')

        with JOBS_LOCK:
            JOBS[job_id].update({
                'state': 'cancelled' if cancelled else 'done',
                'sent': sent,
                'failed': failed,
                'details': details,
                'finished_at': time.time(),
            })

        # If cancelled, ensure campaign status is updated to 'stopped'
        if cancelled and campaign_id is not None and app is not None:
            try:
                with app.app_context():
                    from .models import Campaign, db
                    c = Campaign.query.get(campaign_id)
                    if c:
                        c.status = 'stopped'
                        db.session.commit()
            except Exception:
                logger.exception('Failed to update campaign status after cancel')

    except Exception as exc:
        logger.exception('Background send job failed: %s', exc)
        with JOBS_LOCK:
            JOBS[job_id].update({'state': 'failed', 'error': str(exc), 'finished_at': time.time()})


def _send_personalized_emails(job_id: str, emails: list, email_links: dict, template_html=None, subject=None, campaign_id=None, app=None, stagger_delay_seconds: int = 0):
    """Send personalized emails using campaign template with unique tokens per user."""
    import smtplib
    from email.mime.multipart import MIMEMultipart
    from email.mime.text import MIMEText
    from email.mime.image import MIMEImage
    import re
    
    success = failures = 0
    details = {}

    # Pre-load CID images for this campaign's template
    cid_images = []  # list of dicts: {cid, data, mime_type, filename}
    file_attachments = []  # list of dicts: {filename, data, mime_type}
    if campaign_id and app:
        try:
            with app.app_context():
                from .models import Campaign, TemplateAttachment, EmailTemplate, get_effective_template_images
                campaign = Campaign.query.get(campaign_id)
                if campaign and campaign.template_id:
                    template = EmailTemplate.query.get(campaign.template_id)
                    db_images = get_effective_template_images(template)
                    for img in db_images:
                        cid_images.append({
                            'cid': img.cid,
                            'data': bytes(img.data),
                            'mime_type': img.mime_type,
                            'filename': img.filename,
                        })
                    db_atts = TemplateAttachment.query.filter_by(template_id=campaign.template_id).all()
                    for att in db_atts:
                        file_attachments.append({
                            'filename': att.filename,
                            'data': bytes(att.data),
                            'mime_type': att.mime_type,
                        })
                    logger.info(f"Loaded {len(cid_images)} CID images, {len(file_attachments)} attachments for campaign {campaign_id}")
        except Exception as e:
            logger.warning(f"Could not load CID images/attachments for campaign {campaign_id}: {e}")
    
    # Default SMTP settings - Try SystemSetting first, then sendemails fallback
    smtp_server = getattr(sendemails, 'SMTP_SERVER', 'localhost')
    smtp_port = getattr(sendemails, 'SMTP_PORT', 25)
    smtp_user = getattr(sendemails, 'SMTP_USER', '')
    smtp_password = getattr(sendemails, 'SMTP_PASSWORD', '')
    sender_display = getattr(sendemails, 'SENDER_DISPLAY_NAME', 'Security Team')
    sender_email = smtp_user
    use_tls = False
    use_ssl = False
    
    if app:
        try:
            with app.app_context():
                from .models import SystemSetting, SMTPProfile, EmailTemplate
                
                # 1. Try to get default SMTP Profile
                default_profile = SMTPProfile.query.filter_by(is_default=True).first()
                if default_profile:
                    smtp_server = default_profile.smtp_server
                    smtp_port = default_profile.smtp_port
                    smtp_user = default_profile.smtp_user or ''
                    smtp_password = default_profile.smtp_password or ''
                    sender_display = default_profile.sender_name or sender_display
                    sender_email = default_profile.sender_email
                    use_tls = default_profile.use_tls
                    use_ssl = default_profile.use_ssl
                else:
                    # 2. Fallback to System Settings
                    s_server = SystemSetting.query.get('smtp_server')
                    s_port = SystemSetting.query.get('smtp_port')
                    s_user = SystemSetting.query.get('smtp_user')
                    s_pass = SystemSetting.query.get('smtp_password')
                    s_name = SystemSetting.query.get('sender_name')
                    s_email = SystemSetting.query.get('sender_email')
                    
                    if s_server: smtp_server = s_server.value
                    if s_port: smtp_port = int(s_port.value)
                    if s_user: smtp_user = s_user.value
                    if s_pass: smtp_password = s_pass.value
                    if s_name: sender_display = s_name.value
                    if s_email: sender_email = s_email.value

                # 3. Try to get default template if none provided
                if not template_html:
                    # Try to find the Microsoft template we migrated
                    ms_template = EmailTemplate.query.filter_by(name='Microsoft Quarantine Notification').first()
                    if ms_template:
                        template_html = ms_template.html_content
                        if not subject:
                            subject = ms_template.subject
        except Exception as e:
            logger.warning(f'Could not fetch system settings: {e}')
    
    # Try to get SMTP profile from campaign (overrides defaults)
    smtp_profile_data = None
    if campaign_id and app:
        try:
            with app.app_context():
                from .models import Campaign, SMTPProfile
                campaign = Campaign.query.get(campaign_id)
                if campaign and campaign.smtp_profile_id:
                    smtp_profile = SMTPProfile.query.get(campaign.smtp_profile_id)
                    if smtp_profile:
                        smtp_server = smtp_profile.smtp_server
                        smtp_port = smtp_profile.smtp_port
                        smtp_user = smtp_profile.smtp_user or ''
                        smtp_password = smtp_profile.smtp_password or ''
                        sender_display = smtp_profile.sender_name or sender_display
                        sender_email = smtp_profile.sender_email
                        use_tls = smtp_profile.use_tls
                        use_ssl = smtp_profile.use_ssl
                        # Store enhanced header info for later use
                        smtp_profile_data = {
                            'from_name': smtp_profile.from_name,
                            'reply_to': smtp_profile.reply_to,
                            'custom_headers': smtp_profile.custom_headers
                        }
                        logger.info(f"Using SMTP profile '{smtp_profile.name}' for campaign {campaign_id}")
        except Exception as e:
            logger.warning(f'Could not fetch SMTP profile for campaign: {e}')
    
    # Use default template if still none provided (legacy fallback)
    if not template_html:
        template_html = sendemails.create_email_content("{{FirstName}}", "{{link}}", "{{tracking_pixel}}")
    if not subject:
        subject = getattr(sendemails, 'EMAIL_SUBJECT', 'Important Security Notification')
    
    # Get target data from database if campaign_id provided
    targets_data = {}
    if campaign_id and app:
        try:
            with app.app_context():
                from .models import Target
                targets = Target.query.filter_by(campaign_id=campaign_id).all()
                for t in targets:
                    targets_data[t.email] = {
                        'first_name': t.first_name or '',
                        'last_name': t.last_name or '',
                        'sbu': t.sbu or '',
                        'position': t.position or ''
                    }
        except Exception as e:
            logger.warning(f'Could not fetch target data: {e}')
    
    sent = 0
    failures = 0
    details = {}

    for email, link_data in email_links.items():
        
        # Handle both old format (link, pixel_url) and new format (link, pixel_url, token, logo_url)
        if len(link_data) == 4:
            link, pixel_url, token, logo_url = link_data
        else:
            link, pixel_url = link_data
            token = None
            logo_url = None
        
        # Check for cancellation request
        with JOBS_LOCK:
            job_state = JOBS.get(job_id, {}).get('state')
        if job_state == 'cancelled':
            logger.info(f"Send job {job_id} cancelled before sending to {email}")
            return {'sent': sent, 'failed': failures, 'details': details, 'cancelled': True}
        clean_email = email.replace('\ufeff', '')
        
        # Get target data
        target_info = targets_data.get(clean_email, {})
        first_name = target_info.get('first_name', '')
        last_name = target_info.get('last_name', '')
        
        # Extract name from email if not in database
        if not first_name:
            first_name, _ = sendemails.extract_names_from_email(clean_email)
        
        if not first_name:
            logger.warning(f"Skipping {clean_email} (name extraction failed)")
            failures += 1
            details[clean_email] = {"status": "failed", "error": "name extraction failed"}
            continue
        
        # Personalize the template
        personalized_html = template_html
        personalized_html = personalized_html.replace('{{FirstName}}', first_name)
        personalized_html = personalized_html.replace('{{LastName}}', last_name)
        personalized_html = personalized_html.replace('{{Email}}', clean_email)
        personalized_html = personalized_html.replace('{{link}}', link)
        # Use a more robust tracking pixel tag (no display:none) to ensure it loads
        personalized_html = personalized_html.replace('{{tracking_pixel}}', f'<img src="{pixel_url}" width="1" height="1" style="border:0;margin:0;padding:0;" alt="" />')
        
        # Optional tracked logo placeholders. Keep explicit placeholders working,
        # but do not rewrite existing cid: images because that turns embedded
        # images into remote content and mail clients will block them.
        if logo_url:
            personalized_html = personalized_html.replace('{{tracked_logo}}', logo_url)
            personalized_html = personalized_html.replace('{{logo_url}}', logo_url)
        
        # Also support lowercase variable names for compatibility
        personalized_html = personalized_html.replace('{{firstname}}', first_name)
        personalized_html = personalized_html.replace('{{lastname}}', last_name)
        personalized_html = personalized_html.replace('{{email}}', clean_email)

        # Normalize cid references so HTML and MIME headers match reliably
        # (some templates may include cid:<name> while DB stores <name> or vice versa)
        personalized_html = re.sub(r'cid:\s*<([^>]+)>', r'cid:\1', personalized_html, flags=re.IGNORECASE)
        
        try:
            msg = MIMEMultipart('related')
            msg['Subject'] = subject
            
            # Use from_name if available, otherwise use sender_display
            from_name = sender_display
            if smtp_profile_data and smtp_profile_data.get('from_name'):
                from_name = smtp_profile_data['from_name']
            
            msg['From'] = f"{from_name} <{sender_email}>"
            msg['To'] = clean_email
            
            # Add Reply-To header if specified
            if smtp_profile_data and smtp_profile_data.get('reply_to'):
                msg['Reply-To'] = smtp_profile_data['reply_to']
            
            # Add custom headers if specified
            if smtp_profile_data and smtp_profile_data.get('custom_headers'):
                try:
                    import json
                    headers = json.loads(smtp_profile_data['custom_headers']) if isinstance(smtp_profile_data['custom_headers'], str) else smtp_profile_data['custom_headers']
                    for header_name, header_value in headers.items():
                        msg[header_name] = header_value
                except Exception as e:
                    logger.warning(f"Could not parse custom headers: {e}")
            
            # Build body as multipart/alternative under multipart/related for broad client compatibility
            alt = MIMEMultipart('alternative')
            alt.attach(MIMEText(personalized_html, 'html'))
            msg.attach(alt)

            # ── Attach CID images from the database ──────────────────────────
            for cid_img in cid_images:
                try:
                    # Derive subtype from mime_type (e.g. image/jpeg -> jpeg, image/png -> png)
                    mime_subtype = cid_img['mime_type'].split('/')[-1].lower()
                    # Normalise: jpg extension -> jpeg subtype
                    if mime_subtype == 'jpg':
                        mime_subtype = 'jpeg'
                    
                    part = MIMEImage(cid_img['data'], mime_subtype)
                    cid_bare = cid_img['cid']  # e.g. "unnamed.jpg"
                    part.add_header('Content-ID', f'<{cid_bare}>')
                    part.add_header('Content-Disposition', 'inline', filename=cid_img['filename'])
                    # Add name to Content-Type so Outlook identifies the image correctly
                    part.set_param('name', cid_img['filename'])
                    msg.attach(part)
                    logger.info(f"Attached CID image: cid={cid_bare} filename={cid_img['filename']} mime={cid_img['mime_type']}")
                except Exception as e:
                    logger.error(f"Failed to attach CID image {cid_img.get('filename')}: {e}")

            # ── Attach file attachments (PDF, DOCX, etc.) ────────────────────
            for file_att in file_attachments:
                try:
                    from email.mime.base import MIMEBase
                    from email import encoders
                    main_type, sub_type = file_att['mime_type'].split('/', 1) if '/' in file_att['mime_type'] else ('application', 'octet-stream')
                    part = MIMEBase(main_type, sub_type)
                    part.set_payload(file_att['data'])
                    encoders.encode_base64(part)
                    part.add_header('Content-Disposition', 'attachment', filename=file_att['filename'])
                    msg.attach(part)
                except Exception as e:
                    logger.error(f"Failed to attach file {file_att.get('filename')}: {e}")

            # ── Attach legacy filesystem images (email_images/ folder) ───────
            images = getattr(sendemails, 'IMAGES', {})
            for img_name, img_path in images.items():
                if Path(img_path).exists():
                    with open(img_path, 'rb') as img_file:
                        img = MIMEImage(img_file.read())
                        img.add_header('Content-ID', f'<{img_name}>')
                        img.add_header('Content-Disposition', 'inline')
                        msg.attach(img)
            
            # Connect using appropriate method based on settings
            logger.info(f"Connecting to SMTP: {smtp_server}:{smtp_port} (TLS={use_tls}, SSL={use_ssl})")
            logger.info(f"From: {sender_display} <{sender_email}> To: {clean_email}")
            
            if use_ssl and smtp_port == 465:
                import ssl
                context = ssl.create_default_context()
                with smtplib.SMTP_SSL(smtp_server, smtp_port, context=context) as server:
                    if smtp_user and smtp_password:
                        server.login(smtp_user, smtp_password)
                    result = server.send_message(msg)
                    logger.info(f"SMTP send result: {result}")
            else:
                with smtplib.SMTP(smtp_server, smtp_port) as server:
                    if use_tls:
                        server.starttls()
                    if smtp_user and smtp_password:
                        server.login(smtp_user, smtp_password)
                    result = server.send_message(msg)
                    logger.info(f"SMTP send result: {result}")
            
            sent += 1
            details[clean_email] = {"status": "sent", "error": ""}
            logger.info(f"Sent to {clean_email}")
            
            if campaign_id:
                log_metric('sent', campaign_id, clean_email, token, {'status': 'sent'})

            
        except Exception as e:
            failures += 1
            details[clean_email] = {"status": "failed", "error": str(e)}
            logger.error(f"Failed to send to {clean_email}: {e}")
            
            if campaign_id:
                log_metric('sent', campaign_id, clean_email, token, {'status': 'failed', 'error': str(e)})

    return {'sent': sent, 'failed': failures, 'details': details, 'cancelled': False}



def send_campaign_emails(email_addresses: Iterable[str]) -> Tuple[int, int, Dict[str, str]]:
    """Synchronous send wrapper (keeps previous API) returning (sent, failed, token_map).

    This calls sendemails.generate_unique_links and sendemails.send_emails and returns
    the counts and token_map.
    """
    emails = [e.strip() for e in email_addresses if e and e.strip()]
    if not emails:
        return 0, 0, {}

    if not sendemails:
        logger.error('sendemails.py not available in project root; cannot send emails')
        return 0, len(emails), {}

    if not hasattr(sendemails, 'generate_unique_links') or not hasattr(sendemails, 'send_emails'):
        logger.error('sendemails module does not expose required functions')
        return 0, len(emails), {}

    try:
        email_links, token_map = sendemails.generate_unique_links(emails)
        result = sendemails.send_emails(email_links)

        sent = failed = 0
        if isinstance(result, tuple):
            # support both (sent, failed) and (sent, failed, details)
            sent = result[0]
            failed = result[1] if len(result) > 1 else 0
        else:
            sent = len(email_links)
            failed = max(0, len(emails) - sent)

        # Persist token mapping if available
        try:
            token_file = getattr(sendemails, 'TOKEN_MAPPING_FILE', None)
            if token_file and token_map:
                p = Path(token_file)
                with p.open('a', encoding='utf-8') as fh:
                    for token, email in token_map.items():
                        fh.write(f"{token}:{email}\n")
        except Exception:
            logger.exception('Failed to persist token mapping')

        return sent, failed, token_map

    except Exception as exc:
        logger.exception('Error sending campaign emails: %s', exc)
        return 0, len(emails), {}


def send_campaign_emails_async(email_addresses: Iterable[str], campaign_id: Optional[int] = None, stagger_delay_seconds: int = 0) -> str:
    """Start a background send job and return job_id.

    Job progress is stored in the module-level JOBS dict.
    """
    job_id = str(uuid.uuid4())
    with JOBS_LOCK:
        JOBS[job_id] = {
            'state': 'pending',
            'sent': 0,
            'failed': 0,
            'details': {},
            'created_at': time.time(),
            'started_at': None,
            'finished_at': None,
        }

    # capture app context so background thread can use the database
    try:
        app = current_app._get_current_object()
    except Exception:
        app = None

    thread = threading.Thread(
        target=_run_send_job,
        args=(job_id, list(email_addresses), campaign_id, app, stagger_delay_seconds),
        daemon=True
    )
    thread.start()
    return job_id


def get_job_status(job_id: str) -> Optional[Dict]:
    with JOBS_LOCK:
        return JOBS.get(job_id)


