import unittest
import json
from app import app, db
from models import User, Complaint, ComplaintHistory
from risk_engine import evaluate_fraud_risk

class AntiScamSystemTestCase(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        self.app = app.test_client()

        with app.app_context():
            db.create_all()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_risk_engine_scoring(self):
        """Test risk score calculation logic"""
        complaint_data = {
            'category': 'Financial / UPI Fraud',
            'amount_lost': 150000.0,
            'payment_method': 'UPI / QR Code',
            'phone_number': '+91 99999 88888',
            'email': 'scammer@fake.com',
            'upi_id': 'scam.merchant@ybl',
            'website_url': 'https://fake-phishing.com',
            'evidence_filename': 'screenshot.png'
        }
        indicator_counts = {'phone_count': 3, 'upi_count': 4, 'url_count': 2}

        score, risk_lvl, reasons = evaluate_fraud_risk(complaint_data, indicator_counts)
        self.assertGreaterEqual(score, 81)
        self.assertEqual(risk_lvl, 'CRITICAL')
        self.assertTrue(any('CRITICAL: UPI ID' in r for r in reasons))

    def test_user_registration_and_login(self):
        """Test user signup and login flow"""
        # Register user
        response = self.app.post('/register', data={
            'name': 'Test User',
            'email': 'testuser@example.com',
            'phone': '+1234567890',
            'password': 'password123',
            'confirm_password': 'password123'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)

        # Verify user in database
        with app.app_context():
            u = User.query.filter_by(email='testuser@example.com').first()
            self.assertIsNotNone(u)

        # Login
        login_res = self.app.post('/login', data={
            'email': 'testuser@example.com',
            'password': 'password123'
        }, follow_redirects=True)
        self.assertEqual(login_res.status_code, 200)
        self.assertIn(b'Welcome back', login_res.data)

    def test_public_tracking(self):
        """Test public complaint tracking without login"""
        with app.app_context():
            # Create demo user and complaint
            u = User(name='Public User', email='pub@example.com', password_hash='hash')
            db.session.add(u)
            db.session.commit()

            c = Complaint(
                complaint_id='SCAM-2026-99999',
                user_id=u.id,
                title='Test Phishing Report',
                category='Phishing / Fake Website',
                description='Fake website report',
                incident_date='2026-09-01',
                amount_lost=5000.0,
                risk_score=45,
                risk_level='MEDIUM',
                status='PENDING'
            )
            db.session.add(c)
            db.session.commit()

        # Track via public route
        res = self.app.get('/track?complaint_id=SCAM-2026-99999')
        self.assertEqual(res.status_code, 200)
        self.assertIn(b'SCAM-2026-99999', res.data)
        self.assertIn(b'Phishing / Fake Website', res.data)

if __name__ == '__main__':
    unittest.main()
