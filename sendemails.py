import uuid
import smtplib
import logging
import socket
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from typing import Dict, Tuple, List, Optional
from datetime import datetime
from pathlib import Path
import codecs

# Import configuration
try:
    from config import (
        SMTP_SERVER, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SENDER_DISPLAY_NAME,
        EMAIL_SUBJECT, TRACKING_BASE_URL, EMAILS_FILE, TOKEN_MAPPING_FILE, IMAGES,
        get_local_ip
    )
except ImportError:
    # Fallback defaults if config.py not found
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    SMTP_SERVER = "mail.example.com"
    SMTP_PORT = 25
    SMTP_USER = "alerts@example.com"
    SMTP_PASSWORD = ""
    SENDER_DISPLAY_NAME = "Microsoft Security Center"
    EMAIL_SUBJECT = "Review These Messages - Quarantine Notification"
    # Use HTTPS on port 7443 for production
    TRACKING_BASE_URL = f"https://{get_local_ip()}:7443"
    EMAILS_FILE = "emails.txt"
    TOKEN_MAPPING_FILE = "token_mapping.log"
    IMAGES = {"logo": str(Path(__file__).parent.resolve() / "email_images" / "Microsoft_Logo_512px.png")}

# ==============================================
# TEMPLATE CUSTOMIZATION (can be edited here)
# ==============================================
FILE_NAME = "Activity_Review_Aug_7.pptx"
FILE_SIZE = "8.2 MB"
FILE_SHARER = "Tafara Chidawo"
FILE_SHARE_TIME = datetime.now().strftime("%I:%M %p")

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('email_sender.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# ==============================================
# MICROSOFT QUARANTINE EMAIL TEMPLATE
# ==============================================
def create_email_content(first_name: str, link: str, pixel_url: Optional[str] = None) -> str:
    """Microsoft Quarantine HTML template"""
    current_date = datetime.now().strftime("%d %b %Y %I:%M:%S %p")
    
    # Use a more robust tracking pixel tag (no display:none) to ensure it loads
    pixel_img = f'<img src="{pixel_url}" alt="" width="1" height="1" style="border:0;margin:0;padding:0;" />' if pixel_url else ""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Microsoft Quarantine Notification</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f9f9f9;
        }}
        .container {{
            max-width: 600px;
            margin: auto;
            background: #fff;
            border: 1px solid #ddd;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .header {{
            display: flex;
            align-items: center;
            margin-bottom: 20px;
            border-bottom: 1px solid #e1e1e1;
            padding-bottom: 15px;
        }}
        .header img {{
            height: 32px;
            margin-right: 15px;
        }}
        h2 {{
            color: #333;
            margin: 0;
            font-size: 20px;
        }}
        .highlight {{
            font-weight: bold;
            color: #d83b01;
        }}
        .link {{
            color: #0078d4;
            text-decoration: none;
        }}
        .link:hover {{
            text-decoration: underline;
        }}
        .section {{
            margin-top: 20px;
            padding: 15px;
            background-color: #f3f3f3;
            border-radius: 5px;
            border-left: 4px solid #0078d4;
        }}
        .section h3 {{
            margin-top: 0;
            color: #323130;
            font-size: 16px;
        }}
        .details p {{
            margin: 5px 0;
        }}
        .footer {{
            margin-top: 20px;
            padding-top: 15px;
            border-top: 1px solid #e1e1e1;
            font-size: 12px;
            color: #666;
        }}
        .button {{
            background: #0078d4;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            display: inline-block;
            margin: 15px 0;
            border-radius: 3px;
            font-weight: bold;
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <img src="cid:logo" alt="Microsoft Logo" width="32" height="32">
            <h2>Review These Messages</h2>
        </div>

        <!-- Main Content -->
        <p><span class="highlight">1 message</span> is being held for you to review as of <span class="highlight">{current_date}</span>.</p>
        <p>Review it within <span class="highlight">30 days of the received date</span> by going to the 
            <a href="{link}" class="link">Quarantine page</a> in the Security Center.
        </p>

        <a href="{link}" class="button">Review Message Now</a>

        <!-- Spam Section -->
        <div class="section">
            <h3>Prevented Spam Message</h3>
            <div class="details">
                <p><strong>Sender:</strong> news@myzim.com</p>
                <p><strong>Subject:</strong> Breaking:  RbZw CEO Johnn Steps Down - Here's What Happens Next</p>
                <p><strong>Received:</strong> {current_date}</p>
                <p><strong>Status:</strong> Quarantined - Pending Review</p>
            </div>
        </div>

        <!-- Additional Info -->
        <div class="section">
            <h3>Why is this message held?</h3>
            <p>This message was identified as potential spam or contains links that require additional verification. This is part of our ongoing security measures to protect your account.</p>
        </div>

        <!-- Footer -->
        <div class="footer">
            <p>Microsoft Security Center | One Microsoft Way, Redmond, WA 98052</p>
            <p>This is an automated message. Please do not reply to this email.</p>
            <p>© {datetime.now().year} Microsoft Corporation. All rights reserved.</p>
        </div>
    </div>
    {pixel_img}
</body>
</html>"""

# ==============================================
# CORE FUNCTIONS
# ==============================================
def read_emails_from_txt(file_path: str) -> List[str]:
    try:
        with codecs.open(file_path, 'r', encoding='utf-8-sig') as f:
            return [line.strip() for line in f if '@' in line.strip()]
    except Exception as e:
        logging.error(f"Error reading emails: {e}")
        return []

def extract_names_from_email(email: str) -> Tuple[Optional[str], Optional[str]]:
    try:
        email = email.replace('\ufeff', '')
        local_part = email.split('@')[0]
        if '.' in local_part:
            return local_part.split('.')[0].capitalize(), None
        if len(local_part) >= 6:
            return local_part[:6].capitalize(), None
        return local_part.capitalize(), None
    except Exception as e:
        logging.error(f"Name extraction failed: {e}")
        return "User", None

def generate_unique_links(email_addresses: List[str]) -> Tuple[Dict[str, Tuple[str, str]], Dict[str, str]]:
    links = {}
    token_mapping = {}
    for email in email_addresses:
        clean_email = email.replace('\ufeff', '')
        token = str(uuid.uuid4())
        links[clean_email] = (
            f"{TRACKING_BASE_URL}/track?token={token}",
            f"{TRACKING_BASE_URL}/pixel?token={token}"
        )
        token_mapping[token] = clean_email
    return links, token_mapping

def send_email(to_email: str, subject: str, html_content: str) -> bool:
    """Send a single email (used for test emails).
    
    Args:
        to_email: Recipient email address
        subject: Email subject line
        html_content: HTML content of the email
        
    Returns:
        True if sent successfully, False otherwise
    """
    try:
        msg = MIMEMultipart('related')
        msg['Subject'] = subject
        msg['From'] = f"{SENDER_DISPLAY_NAME} <{SMTP_USER}>"
        msg['To'] = to_email
        
        msg.attach(MIMEText(html_content, 'html'))
        
        # Attach images if available
        for img_name, img_path in IMAGES.items():
            if Path(img_path).exists():
                with open(img_path, 'rb') as img_file:
                    img = MIMEImage(img_file.read())
                    img.add_header('Content-ID', f'<{img_name}>')
                    msg.attach(img)
        
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            if SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
            
        logging.info(f"Test email sent successfully to {to_email}")
        return True
        
    except Exception as e:
        logging.error(f"Failed to send test email to {to_email}: {str(e)}")
        return False

def send_emails(email_links: Dict[str, Tuple[str, str]]) -> Tuple[int, int, Dict[str, Dict[str, str]]]:
    """Send emails and return detailed per-recipient results.

    Returns (sent_count, failed_count, details) where details is a mapping
    email -> {"status": "sent"|"failed", "error": <message or empty>}.
    """
    success = failures = 0
    details: Dict[str, Dict[str, str]] = {}

    for email, (link, pixel_url) in email_links.items():
        clean_email = email.replace('\ufeff', '')
        first_name, _ = extract_names_from_email(clean_email)
        if not first_name:
            first_name = "User"

        try:
            msg = MIMEMultipart('related')
            msg['Subject'] = EMAIL_SUBJECT
            msg['From'] = f"{SENDER_DISPLAY_NAME} <{SMTP_USER}>"
            msg['To'] = clean_email

            # inject external tracking pixel URL into the HTML so the /pixel endpoint is requested
            msg.attach(MIMEText(create_email_content(first_name, link, pixel_url), 'html'))

            # Attach images
            for img_name, img_path in IMAGES.items():
                if Path(img_path).exists():
                    with open(img_path, 'rb') as img_file:
                        img = MIMEImage(img_file.read())
                        img.add_header('Content-ID', f'<{img_name}>')
                        msg.attach(img)
                else:
                    logging.warning(f"Image not found, skipping attachment: {img_path}")

            with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
                if SMTP_PASSWORD:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)

            success += 1
            details[clean_email] = {"status": "sent", "error": ""}
            logging.info(f"Sent to {clean_email}")

        except Exception as e:
            failures += 1
            details[clean_email] = {"status": "failed", "error": str(e)}
            logging.error(f"Failed to send to {clean_email}: {str(e)}")

    logging.info(f"Results: {success} sent, {failures} failed")
    return success, failures, details

# ==============================================
# MAIN EXECUTION
# ==============================================
if __name__ == "__main__":
    try:
        logging.info("Starting email campaign")
        
        # Verify images exist
        for img_path in IMAGES.values():
            if not Path(img_path).exists():
                raise FileNotFoundError(f"Missing image: {img_path}")
        
        emails = read_emails_from_txt(EMAILS_FILE)
        if not emails:
            raise ValueError("No valid emails found")
        
        links, token_mapping = generate_unique_links(emails)
        send_emails(links)
        
        # Save token mapping
        with open(TOKEN_MAPPING_FILE, 'w', encoding='utf-8') as f:
            f.writelines(f"{token}:{email}\n" for token, email in token_mapping.items())
        
        logging.info("Campaign completed successfully")
        
    except Exception as e:
        logging.error(f"Fatal error: {str(e)}")
        exit(1)