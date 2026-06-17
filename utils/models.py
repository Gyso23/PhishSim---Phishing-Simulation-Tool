from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import re

db = SQLAlchemy()


class Campaign(db.Model):
    __tablename__ = 'campaigns'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    subject = db.Column(db.String(255), nullable=True)
    template_html = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(50), default='draft')
    campaign_type = db.Column(db.String(50), nullable=True)  # 'credential_harvest', 'link_click', 'attachment'
    sender_name = db.Column(db.String(255), nullable=True)
    sender_email = db.Column(db.String(255), nullable=True)
    
    # Integration columns
    template_id = db.Column(db.Integer, db.ForeignKey('email_templates.id'), nullable=True)
    landing_page_id = db.Column(db.Integer, db.ForeignKey('landing_pages.id'), nullable=True)
    smtp_profile_id = db.Column(db.Integer, db.ForeignKey('smtp_profiles.id'), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    scheduled_for = db.Column(db.DateTime, nullable=True)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)
    sent_count = db.Column(db.Integer, default=0)
    failed_count = db.Column(db.Integer, default=0)
    clicked_count = db.Column(db.Integer, default=0)
    compromised_count = db.Column(db.Integer, default=0)
    job_id = db.Column(db.String(64), nullable=True)
    
    # Reminder settings
    reminders_enabled = db.Column(db.Boolean, default=False)
    reminder_interval_minutes = db.Column(db.Integer, default=5)  # Send reminder every X minutes
    max_reminders = db.Column(db.Integer, default=12)  # Maximum reminders per user
    reminder_subject = db.Column(db.String(255), nullable=True, default='Reminder: Complete Your Security Assessment')
    reminder_html = db.Column(db.Text, nullable=True)  # Custom reminder email HTML
    reminder_cc = db.Column(db.String(320), nullable=True)  # CC email for reminders
    stagger_seconds = db.Column(db.Integer, default=0, nullable=False, server_default='0')


class Target(db.Model):
    __tablename__ = 'targets'
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=True, index=True)
    email = db.Column(db.String(320), nullable=False, index=True)
    first_name = db.Column(db.String(128), nullable=True)
    last_name = db.Column(db.String(128), nullable=True)
    sbu = db.Column(db.String(128), nullable=True)
    position = db.Column(db.String(128), nullable=True)
    past_target = db.Column(db.Boolean, default=False, index=True)


class Result(db.Model):
    __tablename__ = 'results'
    
    id = db.Column(db.Integer, primary_key=True)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'))
    email = db.Column(db.String(255))
    token = db.Column(db.String(100), unique=True)
    status = db.Column(db.String(50), default='pending')
    error = db.Column(db.Text)  # Error message if send failed
    sent = db.Column(db.Boolean, default=False)
    sent_at = db.Column(db.DateTime)
    opened = db.Column(db.Boolean, default=False)
    opened_at = db.Column(db.DateTime)
    clicked = db.Column(db.Boolean, default=False)
    clicked_at = db.Column(db.DateTime)
    reported = db.Column(db.Boolean, default=False)  # Whether user reported the phishing email
    reported_at = db.Column(db.DateTime)
    submitted = db.Column(db.Boolean, default=False)
    submitted_at = db.Column(db.DateTime)
    credentials = db.Column(db.Text)  # JSON string of captured data
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.Text)
    
    # Questionnaire tracking
    questionnaire_completed = db.Column(db.Boolean, default=False)
    questionnaire_completed_at = db.Column(db.DateTime)
    questionnaire_score = db.Column(db.Integer)  # Score 0-100
    questionnaire_answers = db.Column(db.Text)  # JSON string of answers
    
    # Reminder tracking
    last_reminder_sent = db.Column(db.DateTime)
    reminder_count = db.Column(db.Integer, default=0)



class EmailTemplate(db.Model):
    __tablename__ = 'email_templates'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    subject = db.Column(db.String(255), nullable=True)
    html_content = db.Column(db.Text, nullable=True)
    tags = db.Column(db.String(500), nullable=True)  # Comma-separated tags
    sender_name = db.Column(db.String(255), nullable=True)
    sender_email = db.Column(db.String(255), nullable=True)
    
    # Integration columns
    default_landing_page_id = db.Column(db.Integer, db.ForeignKey('landing_pages.id'), nullable=True)
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationship to embedded images
    images = db.relationship('TemplateImage', backref='template', lazy=True, cascade='all, delete-orphan')
    # Relationship to file attachments
    attachments = db.relationship('TemplateAttachment', backref='template', lazy=True, cascade='all, delete-orphan')


def extract_template_cid_refs(html_content):
    """Return the set of cid values referenced in template HTML."""
    html = html_content or ''
    return set(re.findall(r'cid:\s*<?([^>"\'\s]+)>?', html, flags=re.IGNORECASE))


def get_effective_template_images(template):
    """Return images for a template, recovering from older duplicate split records.

    A previous save bug could leave HTML on one template row and CID images on another
    row with the same name. This helper keeps the current template images first and
    fills in any missing CID references from sibling templates with the same name.
    """
    if not template:
        return []

    refs = extract_template_cid_refs(template.html_content)
    images_by_cid = {img.cid: img for img in getattr(template, 'images', [])}

    missing = refs.difference(images_by_cid.keys())
    if missing:
        siblings = EmailTemplate.query.filter(
            EmailTemplate.name == template.name,
            EmailTemplate.id != template.id,
        ).all()
        for sibling in siblings:
            for img in getattr(sibling, 'images', []):
                if img.cid in missing and img.cid not in images_by_cid:
                    images_by_cid[img.cid] = img

    return list(images_by_cid.values())


class TemplateImage(db.Model):
    """Stores images embedded in email templates as CID attachments."""
    __tablename__ = 'template_images'
    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(db.Integer, db.ForeignKey('email_templates.id'), nullable=False)
    cid = db.Column(db.String(255), nullable=False)        # e.g. "logo" → used as cid:logo in HTML
    filename = db.Column(db.String(255), nullable=False)   # original filename e.g. "logo.png"
    mime_type = db.Column(db.String(100), nullable=False, default='image/png')
    data = db.Column(db.LargeBinary, nullable=False)       # raw image bytes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class TemplateAttachment(db.Model):
    """Stores file attachments (PDF, DOCX, etc.) sent with email templates."""
    __tablename__ = 'template_attachments'
    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(db.Integer, db.ForeignKey('email_templates.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)   # original filename e.g. "invoice.pdf"
    mime_type = db.Column(db.String(100), nullable=False, default='application/octet-stream')
    data = db.Column(db.LargeBinary, nullable=False)       # raw file bytes
    size = db.Column(db.Integer, nullable=True)            # file size in bytes
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class SMTPProfile(db.Model):
    __tablename__ = 'smtp_profiles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    smtp_server = db.Column(db.String(255), nullable=False)
    smtp_port = db.Column(db.Integer, nullable=False, default=25)
    smtp_user = db.Column(db.String(255), nullable=True)
    smtp_password = db.Column(db.String(255), nullable=True)  # TODO: Encrypt in production
    sender_name = db.Column(db.String(255), nullable=True)
    sender_email = db.Column(db.String(255), nullable=False)
    from_name = db.Column(db.Text, nullable=True)  # Display name in email client
    reply_to = db.Column(db.Text, nullable=True)  # Reply-to email address
    custom_headers = db.Column(db.Text, nullable=True)  # JSON string of custom headers
    use_tls = db.Column(db.Boolean, default=False)
    use_ssl = db.Column(db.Boolean, default=False)
    is_default = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class LandingPage(db.Model):
    __tablename__ = 'landing_pages'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    page_type = db.Column(db.String(50), nullable=False, default='simple')  # simple, credential_harvest, questionnaire
    html_content = db.Column(db.Text, nullable=True)
    custom_css = db.Column(db.Text, nullable=True)
    questions = db.Column(db.Text, nullable=True)  # JSON string for questionnaire fields
    capture_data = db.Column(db.Boolean, default=True)
    redirect_url = db.Column(db.String(500), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class LandingPageSubmission(db.Model):
    __tablename__ = 'landing_page_submissions'
    id = db.Column(db.Integer, primary_key=True)
    landing_page_id = db.Column(db.Integer, db.ForeignKey('landing_pages.id'), nullable=False)
    campaign_id = db.Column(db.Integer, db.ForeignKey('campaigns.id'), nullable=True)
    email = db.Column(db.String(320), nullable=True)  # Target email if known
    submitted_data = db.Column(db.Text, nullable=True)  # JSON string of form data
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)


class SystemSetting(db.Model):
    __tablename__ = 'system_settings'
    key = db.Column(db.String(100), primary_key=True)
    value = db.Column(db.Text, nullable=True)
    description = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

