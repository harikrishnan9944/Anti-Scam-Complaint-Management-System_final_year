"""
Rule-Based Preliminary Fraud Risk Engine for Anti-Scam System.
Evaluates complaint metrics transparently using deterministic rules.
Calculates Risk Score (0-100), Risk Level (LOW, MEDIUM, HIGH, CRITICAL), and transparent reason bullet points.
"""

def evaluate_fraud_risk(complaint_data, indicator_counts=None):
    """
    Evaluates fraud risk score for a complaint.
    
    complaint_data dict includes:
    - category
    - amount_lost
    - payment_method
    - phone_number
    - upi_id
    - website_url
    - email
    - evidence_filename
    
    indicator_counts dict (optional) includes:
    - phone_count: number of times phone_number appears across all complaints
    - upi_count: number of times upi_id appears across all complaints
    - url_count: number of times website_url appears across all complaints
    """
    if indicator_counts is None:
        indicator_counts = {}

    score = 0
    reasons = []

    category = (complaint_data.get('category') or '').strip().lower()
    amount_lost = float(complaint_data.get('amount_lost') or 0.0)
    payment_method = (complaint_data.get('payment_method') or '').strip().lower()
    phone_number = (complaint_data.get('phone_number') or '').strip()
    upi_id = (complaint_data.get('upi_id') or '').strip()
    website_url = (complaint_data.get('website_url') or '').strip()
    email = (complaint_data.get('email') or '').strip()
    evidence = complaint_data.get('evidence_filename')

    # 1. Category Base Weight
    if 'investment' in category or 'job' in category:
        score += 25
        reasons.append("High-risk category (Job/Investment Scam with high systemic target risk)")
    elif 'financial' in category or 'upi' in category or 'banking' in category:
        score += 20
        reasons.append("Financial & payment channel scam target")
    elif 'crypto' in category or 'wallet' in category:
        score += 25
        reasons.append("Non-reversible transaction ecosystem (Crypto / Wallet)")
    elif 'phishing' in category or 'fake website' in category:
        score += 15
        reasons.append("Phishing infrastructure & domain spoofing detected")
    elif 'tech support' in category or 'lottery' in category:
        score += 15
        reasons.append("Social engineering tactics commonly associated with organized fraud")
    else:
        score += 10
        reasons.append("Standard fraud report classification")

    # 2. Financial Amount Impact
    if amount_lost >= 100000:
        score += 30
        reasons.append(f"Severe financial impact reported (Amount >= 100,000)")
    elif amount_lost >= 25000:
        score += 20
        reasons.append(f"High financial loss reported (Amount >= 25,000)")
    elif amount_lost >= 5000:
        score += 15
        reasons.append(f"Moderate financial loss reported (Amount >= 5,000)")
    elif amount_lost > 0:
        score += 10
        reasons.append(f"Direct monetary loss reported")

    # 3. Payment Method Vulnerability Weight
    if 'crypto' in payment_method:
        score += 20
        reasons.append("Irreversible payment gateway (Cryptocurrency)")
    elif any(k in payment_method for k in ['wire', 'bank transfer', 'imps', 'neft', 'rtgs']):
        score += 15
        reasons.append("Direct bank transfer mechanism utilized")
    elif 'upi' in payment_method or 'qr' in payment_method:
        score += 15
        reasons.append("Instant peer-to-peer UPI transfer channel used")
    elif 'gift card' in payment_method or 'voucher' in payment_method:
        score += 20
        reasons.append("Untraceable voucher / gift card payment requested")
    elif any(k in payment_method for k in ['card', 'credit', 'debit']):
        score += 10
        reasons.append("Payment processed via card authorization")

    # 4. Evidence Provided
    if evidence:
        reasons.append("Supporting visual / document evidence uploaded")

    # 5. Suspicious Information Quality
    indicators_provided = 0
    if phone_number:
        indicators_provided += 1
    if upi_id:
        indicators_provided += 1
    if website_url:
        indicators_provided += 1
    if email:
        indicators_provided += 1

    if indicators_provided >= 3:
        score += 10
        reasons.append("Multiple verifiable suspicious indicators provided")
    elif indicators_provided >= 1:
        score += 5

    # 6. Pattern Detection - Cross Database Repeat Matches
    phone_repeat = indicator_counts.get('phone_count', 0)
    upi_repeat = indicator_counts.get('upi_count', 0)
    url_repeat = indicator_counts.get('url_count', 0)

    if upi_repeat > 1:
        add_pts = min(25, 15 + (upi_repeat - 1) * 5)
        score += add_pts
        reasons.append(f"CRITICAL: UPI ID ({upi_id}) linked to {upi_repeat} distinct complaints across platform")
    
    if phone_repeat > 1:
        add_pts = min(20, 10 + (phone_repeat - 1) * 5)
        score += add_pts
        reasons.append(f"WARNING: Phone number ({phone_number}) reported in {phone_repeat} separate incidents")

    if url_repeat > 1:
        add_pts = min(20, 10 + (url_repeat - 1) * 5)
        score += add_pts
        reasons.append(f"WARNING: Website domain ({website_url}) flagged in {url_repeat} complaint reports")

    # Cap score between 0 and 100
    score = max(0, min(100, score))

    # Categorize Risk Level
    if score >= 81:
        risk_level = "CRITICAL"
    elif score >= 61:
        risk_level = "HIGH"
    elif score >= 31:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return score, risk_level, reasons
