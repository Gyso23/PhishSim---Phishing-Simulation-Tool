import os
import sys
import random
from datetime import datetime, timedelta

# Ensure we can import app and models
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app, models_db
from utils.models import Campaign, Target, Result, LandingPage, SMTPProfile, EmailTemplate

def seed_db():
    with app.app_context():
        # Clean existing data just in case
        models_db.drop_all()
        models_db.create_all()

        print("Seeding database with sample data...")

        # 1. Create SMTP Profile
        smtp = SMTPProfile(
            name="Default SMTP",
            smtp_server="smtp.example.com",
            smtp_port=587,
            sender_email="alerts@example.com",
            sender_name="Security Alert",
            is_default=True
        )
        models_db.session.add(smtp)

        # 2. Create Landing Page
        lp = LandingPage(
            name="Standard Credential Harvest",
            page_type="credential_harvest",
            html_content="<h1>Login Required</h1><form><input type='text' name='username'/><input type='password' name='password'/></form>"
        )
        models_db.session.add(lp)

        # 3. Create Email Template
        template = EmailTemplate(
            name="Password Expiry Notice",
            subject="Action Required: Password Expiring Soon",
            html_content="<p>Your password will expire in 24 hours. Please click the link to reset it.</p>"
        )
        models_db.session.add(template)
        models_db.session.commit()

        # Generate some SBU departments
        departments = ["Sales", "Marketing", "Engineering", "HR", "Finance", "IT", "HQ", "Operations"]

        # Helper to generate targets and results for a campaign
        def add_campaign_data(campaign, num_targets, open_rate, click_rate, compromise_rate):
            targets = []
            for i in range(num_targets):
                dept = random.choice(departments)
                t = Target(
                    campaign_id=campaign.id,
                    email=f"user{i+1}.{dept.lower()}@example.com",
                    first_name=f"User{i+1}",
                    last_name=f"Doe",
                    sbu=dept,
                    position="Staff"
                )
                models_db.session.add(t)
                targets.append(t)
            
            models_db.session.commit()

            sent_count = num_targets
            opened_count = 0
            clicked_count = 0
            compromised_count = 0

            for t in targets:
                # Determine outcome
                opened = random.random() < open_rate
                clicked = opened and random.random() < click_rate
                compromised = clicked and random.random() < compromise_rate

                r = Result(
                    campaign_id=campaign.id,
                    email=t.email,
                    token=f"token_{t.id}_{campaign.id}",
                    status="sent" if not clicked else "clicked",
                    sent=True,
                    sent_at=campaign.started_at + timedelta(minutes=random.randint(1, 60)),
                    opened=opened,
                    opened_at=(campaign.started_at + timedelta(minutes=random.randint(60, 120))) if opened else None,
                    clicked=clicked,
                    clicked_at=(campaign.started_at + timedelta(minutes=random.randint(120, 180))) if clicked else None,
                    submitted=compromised,
                    submitted_at=(campaign.started_at + timedelta(minutes=random.randint(180, 240))) if compromised else None
                )
                models_db.session.add(r)

                if opened: opened_count += 1
                if clicked: clicked_count += 1
                if compromised: compromised_count += 1

            campaign.sent_count = sent_count
            campaign.clicked_count = clicked_count
            campaign.compromised_count = compromised_count
            models_db.session.commit()

        # 4. Create Completed Campaign
        c1 = Campaign(
            name="Q1 Phishing Simulation",
            description="Company-wide quarterly phishing assessment.",
            subject="Important Q1 Updates",
            status="completed",
            campaign_type="credential_harvest",
            smtp_profile_id=smtp.id,
            landing_page_id=lp.id,
            created_at=datetime.utcnow() - timedelta(days=90),
            started_at=datetime.utcnow() - timedelta(days=88),
            finished_at=datetime.utcnow() - timedelta(days=80),
        )
        models_db.session.add(c1)
        models_db.session.commit()
        add_campaign_data(c1, 150, open_rate=0.4, click_rate=0.3, compromise_rate=0.5)

        # 5. Create Running Campaign
        c2 = Campaign(
            name="Q2 Security Drill - Urgent Update",
            description="Testing awareness of urgent IT updates.",
            subject="Urgent: System Maintenance Required",
            status="running",
            campaign_type="link_click",
            smtp_profile_id=smtp.id,
            landing_page_id=lp.id,
            created_at=datetime.utcnow() - timedelta(days=2),
            started_at=datetime.utcnow() - timedelta(days=1),
        )
        models_db.session.add(c2)
        models_db.session.commit()
        add_campaign_data(c2, 320, open_rate=0.6, click_rate=0.2, compromise_rate=0.1)

        # 6. Create Draft Campaign
        c3 = Campaign(
            name="Targeted Finance Spear-Phishing",
            description="Highly targeted campaign for the finance team.",
            subject="Invoice #49281 Overdue",
            status="draft",
            campaign_type="credential_harvest",
            smtp_profile_id=smtp.id,
            landing_page_id=lp.id,
            created_at=datetime.utcnow() - timedelta(hours=5),
        )
        models_db.session.add(c3)
        models_db.session.commit()

        print("Database seeded successfully!")

if __name__ == '__main__':
    seed_db()
