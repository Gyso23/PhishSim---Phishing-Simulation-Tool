#!/usr/bin/env python3
"""
Reminder Email Service for Phishing Simulation Platform
Sends reminder emails every N minutes to users who clicked but have not completed the
security assessment.  All configuration (interval, max reminders, sender, template)
is read from the SystemSetting table so it can be managed from the Settings page.

Reminders are ALWAYS sent from the dedicated reminder sender — never from the
campaign's own SMTP sender address.

Run as a background process:
    python reminder_service.py

Or use --once for cron / Task Scheduler:
    python reminder_service.py --once
"""

import os
import sys
import time
import smtplib
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask
from utils.models import db, Result, Campaign, SMTPProfile, SystemSetting

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('reminder_service.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Fallback values used only when DB settings are absent
_DEFAULT_INTERVAL    = 5
_DEFAULT_MAX         = 12
_DEFAULT_SUBJECT     = '⚠️ REMINDER: Complete Your Security Assessment'
_DEFAULT_SENDER_NAME = 'Information Security'
_DEFAULT_TEMPLATE    = '''<!DOCTYPE html>
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

CHECK_INTERVAL_SECONDS = 60  # How often the service loop wakes up to check


def create_app():
    """Create Flask app for database access."""
    app = Flask(__name__)
    try:
        from config import SQLALCHEMY_DATABASE_URI
        app.config['SQLALCHEMY_DATABASE_URI'] = SQLALCHEMY_DATABASE_URI
    except ImportError:
        db_path = os.path.join(os.path.dirname(__file__), 'data', 'phishing.db')
        app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)
    return app


def _get_setting(key, default=None):
    """Read a single SystemSetting value (must be called inside app context)."""
    row = SystemSetting.query.get(key)
    return row.value if row and row.value is not None else default


def _load_reminder_config():
    """
    Load all reminder configuration from the database.
    Returns a dict with all settings needed by the service.
    """
    interval    = int(_get_setting('reminder_interval',    _DEFAULT_INTERVAL))
    max_rem     = int(_get_setting('max_reminders',        _DEFAULT_MAX))
    subject     = _get_setting('reminder_subject',         _DEFAULT_SUBJECT)
    sender_name = _get_setting('reminder_sender_name',     _DEFAULT_SENDER_NAME)
    sender_email= _get_setting('reminder_sender_email',    '')
    profile_id  = _get_setting('reminder_smtp_profile_id', '')
    template    = _get_setting('reminder_email_template',  _DEFAULT_TEMPLATE)

    return {
        'interval':     interval,
        'max_reminders':max_rem,
        'subject':      subject,
        'sender_name':  sender_name,
        'sender_email': sender_email,
        'profile_id':   int(profile_id) if profile_id else None,
        'template':     template,
    }


def _get_smtp_profile(profile_id):
    """
    Return the SMTP profile to use for reminders.
    - If profile_id is set, use that profile.
    - Otherwise fall back to the default profile.
    - Returns None if no profile exists at all.
    """
    if profile_id:
        profile = SMTPProfile.query.get(profile_id)
        if profile:
            return profile
        logger.warning(f"Reminder SMTP profile id={profile_id} not found, falling back to default.")

    profile = SMTPProfile.query.filter_by(is_default=True).first()
    if not profile:
        profile = SMTPProfile.query.first()
    return profile


def send_reminder_email(smtp_profile, reminder_sender_name, reminder_sender_email,
                        subject, html_template, to_email, landing_page_url):
    """
    Send one reminder email.

    The From address is always `reminder_sender_name <reminder_sender_email>`,
    never the campaign sender.  The smtp_profile supplies delivery credentials.
    """
    if not reminder_sender_email:
        logger.error("Reminder sender email is not configured.  "
                     "Set 'reminder_sender_email' in System Settings.")
        return False

    try:
        html_content = html_template.replace('{landing_page_url}', landing_page_url)

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From']    = f"{reminder_sender_name} <{reminder_sender_email}>"
        msg['To']      = to_email
        msg.attach(MIMEText(html_content, 'html'))

        # Establish SMTP connection using the profile's server/credentials
        if smtp_profile.use_ssl:
            server = smtplib.SMTP_SSL(smtp_profile.smtp_server, smtp_profile.smtp_port)
        else:
            server = smtplib.SMTP(smtp_profile.smtp_server, smtp_profile.smtp_port)
            if smtp_profile.use_tls:
                server.starttls()

        if smtp_profile.smtp_user and smtp_profile.smtp_password:
            server.login(smtp_profile.smtp_user, smtp_profile.smtp_password)

        # Send with the dedicated reminder address as envelope sender
        server.sendmail(reminder_sender_email, to_email, msg.as_string())
        server.quit()

        logger.info(f"Reminder sent to {to_email} (from: {reminder_sender_email})")
        return True

    except Exception as e:
        logger.error(f"Failed to send reminder to {to_email}: {e}")
        return False


def process_reminders(app):
    """Find users who need reminders and send them."""
    with app.app_context():
        cfg = _load_reminder_config()

        if not cfg['sender_email']:
            logger.error("No reminder_sender_email configured in System Settings.  "
                         "Please set it on the Settings page before running reminders.")
            return 0

        smtp_profile = _get_smtp_profile(cfg['profile_id'])
        if not smtp_profile:
            logger.error("No SMTP profile available.  Cannot send reminders.")
            return 0

        now = datetime.now()
        reminder_threshold = now - timedelta(minutes=cfg['interval'])

        results_needing_reminder = Result.query.filter(
            Result.clicked == True,
            Result.questionnaire_completed == False,
            Result.reminder_count < cfg['max_reminders'],
            db.or_(
                Result.last_reminder_sent == None,
                Result.last_reminder_sent < reminder_threshold
            )
        ).all()

        if not results_needing_reminder:
            logger.debug("No reminders needed at this time")
            return 0

        sent_count = 0

        for result in results_needing_reminder:
            campaign = Campaign.query.get(result.campaign_id)
            if not campaign:
                continue

            try:
                from config import TRACKING_BASE_URL
                base_url = TRACKING_BASE_URL
            except Exception:
                base_url = "https://192.168.1.100:7443"

            landing_page_id  = getattr(campaign, 'landing_page_id', 1) or 1
            landing_page_url = (
                f"{base_url}/lp/{landing_page_id}"
                f"?email={result.email}&campaign_id={result.campaign_id}"
            )

            if send_reminder_email(
                smtp_profile,
                cfg['sender_name'],
                cfg['sender_email'],
                cfg['subject'],
                cfg['template'],
                result.email,
                landing_page_url
            ):
                result.last_reminder_sent = now
                result.reminder_count    += 1
                sent_count               += 1

        db.session.commit()
        logger.info(f"Sent {sent_count} reminder emails")
        return sent_count


def run_service():
    """Main service loop."""
    logger.info("Starting Reminder Email Service")
    app = create_app()
    with app.app_context():
        cfg = _load_reminder_config()
    logger.info(f"Reminder interval: {cfg['interval']} min  |  Max per user: {cfg['max_reminders']}")
    logger.info(f"Reminder sender: {cfg['sender_name']} <{cfg['sender_email'] or 'NOT SET'}>")

    while True:
        try:
            process_reminders(app)
        except Exception as e:
            logger.error(f"Error processing reminders: {e}")
        time.sleep(CHECK_INTERVAL_SECONDS)


def run_once():
    """Run the reminder check once (for testing or cron jobs)."""
    logger.info("Running single reminder check")
    app = create_app()
    sent = process_reminders(app)
    logger.info(f"Completed. Sent {sent} reminders.")
    return sent


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description='Reminder Email Service')
    parser.add_argument('--once', action='store_true', help='Run once and exit (for cron jobs)')
    args = parser.parse_args()
    if args.once:
        run_once()
    else:
        run_service()
