import os
import random
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from models import User, Complaint, ComplaintHistory
from risk_engine import evaluate_fraud_risk

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_complaint_id(db):
    year = datetime.now().year
    prefix = f"SCAM-{year}-"
    # Find max existing numeric ID with prefix
    last_complaint = Complaint.query.filter(Complaint.complaint_id.like(f"{prefix}%")).order_by(Complaint.id.desc()).first()
    if last_complaint:
        try:
            last_num = int(last_complaint.complaint_id.split('-')[-1])
            new_num = last_num + 1
        except ValueError:
            new_num = 1
    else:
        new_num = 1
    return f"{prefix}{new_num:05d}"

def get_indicator_counts(complaint_data):
    counts = {'phone_count': 0, 'upi_count': 0, 'url_count': 0}
    phone = (complaint_data.get('phone_number') or '').strip()
    upi = (complaint_data.get('upi_id') or '').strip()
    url = (complaint_data.get('website_url') or '').strip()

    if phone:
        counts['phone_count'] = Complaint.query.filter(Complaint.phone_number == phone).count()
    if upi:
        counts['upi_count'] = Complaint.query.filter(Complaint.upi_id == upi).count()
    if url:
        counts['url_count'] = Complaint.query.filter(Complaint.website_url == url).count()

    return counts

def get_related_complaints(complaint):
    """Finds other complaints that share phone, upi, or url with the given complaint."""
    related = set()
    
    if complaint.phone_number:
        matches = Complaint.query.filter(Complaint.phone_number == complaint.phone_number, Complaint.id != complaint.id).all()
        for m in matches:
            related.add(m)
            
    if complaint.upi_id:
        matches = Complaint.query.filter(Complaint.upi_id == complaint.upi_id, Complaint.id != complaint.id).all()
        for m in matches:
            related.add(m)
            
    if complaint.website_url:
        matches = Complaint.query.filter(Complaint.website_url == complaint.website_url, Complaint.id != complaint.id).all()
        for m in matches:
            related.add(m)

    return list(related)

def seed_initial_data(db):
    """Seeds database with realistic initial test accounts and complaints if fresh."""
    if User.query.count() > 0:
        return  # Already seeded

    print("[Seed Data] Populating initial demo data...")
    
    # 1. Create Admin
    admin = User(
        name="Cyber Admin",
        email="admin@antiscam.gov",
        phone="+1 800-555-0199",
        password_hash=generate_password_hash("admin123"),
        role="admin",
        status="active"
    )
    
    # 2. Create Users
    user1 = User(
        name="Rahul Sharma",
        email="rahul.sharma@example.com",
        phone="+91 98765 43210",
        password_hash=generate_password_hash("user123"),
        role="user",
        status="active"
    )
    user2 = User(
        name="Priya Patel",
        email="priya.patel@example.com",
        phone="+91 91234 56789",
        password_hash=generate_password_hash("user123"),
        role="user",
        status="active"
    )
    user3 = User(
        name="Anish Verma",
        email="anish.verma@example.com",
        phone="+91 99887 76655",
        password_hash=generate_password_hash("user123"),
        role="user",
        status="active"
    )

    db.session.add_all([admin, user1, user2, user3])
    db.session.commit()

    # 3. Create Sample Complaints with varying categories, risk levels, and repeat indicators
    sample_complaints = [
        {
            "user_id": user1.id,
            "title": "Unauthorized UPI Transfer via Fake QR Code",
            "category": "Financial / UPI Fraud",
            "description": "Scammer posing as a buyer on OLX asked me to scan a QR code to receive token money. Scanning it deducted Rs 45,000 from my SBI account instantly.",
            "incident_date": (datetime.now() - timedelta(days=2)).strftime("%Y-%m-%d"),
            "incident_time": "14:30",
            "amount_lost": 45000.0,
            "payment_method": "UPI / QR Code",
            "phone_number": "+91 98989 12345",
            "email": "paytm.support.fake@gmail.com",
            "upi_id": "fastpay.olx@ybl",
            "website_url": "https://quick-refund-claim.top",
            "social_media_account": "@olx_quick_buy",
            "status": "INVESTIGATING",
            "admin_remarks": "Bank nodal officer notified to block UPI VPA."
        },
        {
            "user_id": user2.id,
            "title": "Fake Part-Time Telegram Job Scam",
            "category": "Job / Investment Scam",
            "description": "Recruited via WhatsApp to rate YouTube videos. Initially received Rs 500 profit, then pushed to deposit Rs 1,20,000 for crypto trading tier upgrade. Cashout blocked.",
            "incident_date": (datetime.now() - timedelta(days=5)).strftime("%Y-%m-%d"),
            "incident_time": "11:15",
            "amount_lost": 120000.0,
            "payment_method": "Cryptocurrency",
            "phone_number": "+91 98989 12345",  # Repeated phone number!
            "email": "hr@global-task-corp.site",
            "upi_id": "fastpay.olx@ybl",  # Repeated UPI ID!
            "website_url": "https://task-tasker-level99.com",
            "social_media_account": "Telegram: @HR_Anna_Global",
            "status": "UNDER_REVIEW",
            "admin_remarks": "Indicator match with complaint SCAM-2026-00001. Escalated to cyber cell."
        },
        {
            "user_id": user3.id,
            "title": "Bank Account Suspended Phishing SMS",
            "category": "Phishing / Fake Website",
            "description": "Received SMS claiming my HDFC netbanking account would be locked if KYC was not updated within 2 hours. Clicked link and entered OTP.",
            "incident_date": (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d"),
            "incident_time": "09:45",
            "amount_lost": 18500.0,
            "payment_method": "Bank Transfer / IMPS",
            "phone_number": "+91 97777 88888",
            "email": "service@hdfc-update-kyc.org",
            "upi_id": "hdfc.kyc.portal@icici",
            "website_url": "https://quick-refund-claim.top", # Repeated website URL!
            "social_media_account": "SMS Sender: VM-HDFCBK",
            "status": "PENDING",
            "admin_remarks": "Awaiting domain registry takedown request."
        },
        {
            "user_id": user1.id,
            "title": "Fake E-Commerce Luxury Watch Purchase",
            "category": "Online Shopping Fraud",
            "description": "Ordered a discounted watch from Instagram sponsored ad. Paid Rs 3,499 via debit card. Received a plastic toy instead of product. Merchant website unreachable.",
            "incident_date": (datetime.now() - timedelta(days=10)).strftime("%Y-%m-%d"),
            "incident_time": "18:20",
            "amount_lost": 3499.0,
            "payment_method": "Credit / Debit Card",
            "phone_number": "+91 94444 33333",
            "email": "support@luxus-store.in",
            "upi_id": "",
            "website_url": "https://luxus-deals-india.shop",
            "social_media_account": "@luxus_watch_bazaar",
            "status": "RESOLVED",
            "admin_remarks": "Chargeback initiated via card issuer. Merchant account blacklisted."
        },
        {
            "user_id": user2.id,
            "title": "Impersonation of Friend on Instagram Emergency Loan",
            "category": "Social Media Impersonation",
            "description": "A cloned Instagram account of my college friend messaged asking for urgent Rs 12,000 for medical emergency. Sent via PhonePe.",
            "incident_date": (datetime.now() - timedelta(days=7)).strftime("%Y-%m-%d"),
            "incident_time": "22:00",
            "amount_lost": 12000.0,
            "payment_method": "UPI / QR Code",
            "phone_number": "+91 98989 12345",  # Repeated phone number!
            "email": "",
            "upi_id": "emergency.med@paytm",
            "website_url": "",
            "social_media_account": "@priya_patel_official_clone",
            "status": "PENDING",
            "admin_remarks": ""
        }
    ]

    for idx, c_info in enumerate(sample_complaints, start=1):
        complaint_id = f"SCAM-{datetime.now().year}-{idx:05d}"
        
        # Calculate risk score
        score, risk_lvl, reasons = evaluate_fraud_risk(c_info, indicator_counts={})

        comp = Complaint(
            complaint_id=complaint_id,
            user_id=c_info['user_id'],
            title=c_info['title'],
            category=c_info['category'],
            description=c_info['description'],
            incident_date=c_info['incident_date'],
            incident_time=c_info['incident_time'],
            amount_lost=c_info['amount_lost'],
            payment_method=c_info['payment_method'],
            phone_number=c_info['phone_number'],
            email=c_info['email'],
            upi_id=c_info['upi_id'],
            website_url=c_info['website_url'],
            social_media_account=c_info['social_media_account'],
            risk_score=score,
            risk_level=risk_lvl,
            status=c_info['status'],
            admin_remarks=c_info['admin_remarks'],
            created_at=datetime.utcnow() - timedelta(days=10 - idx)
        )
        comp.risk_reasons = reasons
        db.session.add(comp)
        db.session.flush()

        # Add timeline history
        history_item1 = ComplaintHistory(
            complaint_id=comp.id,
            status='PENDING',
            remarks='Complaint registered in anti-scam portal.',
            updated_by_name='System',
            updated_at=comp.created_at
        )
        db.session.add(history_item1)

        if comp.status != 'PENDING':
            history_item2 = ComplaintHistory(
                complaint_id=comp.id,
                status=comp.status,
                remarks=comp.admin_remarks or f'Status updated to {comp.status}',
                updated_by_name='Cyber Admin',
                updated_at=comp.created_at + timedelta(hours=6)
            )
            db.session.add(history_item2)

    db.session.commit()
    
    # Re-evaluate all risk scores with complete cross-database repeat counts!
    all_complaints = Complaint.query.all()
    for c in all_complaints:
        c_dict = {
            'category': c.category,
            'amount_lost': c.amount_lost,
            'payment_method': c.payment_method,
            'phone_number': c.phone_number,
            'upi_id': c.upi_id,
            'website_url': c.website_url,
            'email': c.email,
            'evidence_filename': c.evidence_filename
        }
        counts = get_indicator_counts(c_dict)
        score, risk_lvl, reasons = evaluate_fraud_risk(c_dict, indicator_counts=counts)
        c.risk_score = score
        c.risk_level = risk_lvl
        c.risk_reasons = reasons

    db.session.commit()
    print(f"[Seed Data] Seeded {User.query.count()} users and {Complaint.query.count()} complaints successfully!")
