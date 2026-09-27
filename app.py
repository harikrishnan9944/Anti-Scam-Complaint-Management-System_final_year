import os
from dotenv import load_dotenv

load_dotenv()

from functools import wraps
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from models import db, User, Complaint, ComplaintHistory
from risk_engine import evaluate_fraud_risk
from utils import (
    allowed_file, generate_complaint_id, get_indicator_counts, 
    get_related_complaints, seed_initial_data
)

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'anti-scam-cyber-secret-key-2026-secure')
app.config['SECRET_KEY'] = app.secret_key
app.config['MONGO_URI'] = os.environ.get('MONGO_URI', 'mongodb://localhost:27017/antiscam_db')

# Upload Folder Configuration (Use /tmp on Vercel or read-only environments)
if os.environ.get('VERCEL') or os.environ.get('AWS_LAMBDA_FUNCTION_NAME'):
    app.config['UPLOAD_FOLDER'] = '/tmp/uploads'
else:
    app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')

app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB Max

# Ensure Uploads directory exists fail-safely
try:
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
except Exception as e:
    print(f"[Uploads Dir Warning] {e}")

db.init_app(app)

# =========================================================================
# AUTHENTICATION DECORATORS
# =========================================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in as Administrator.', 'warning')
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            flash('Access denied. Administrator privileges required.', 'danger')
            return redirect(url_for('user_dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# =========================================================================
# PUBLIC & AUTH ROUTES
# =========================================================================
@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return render_template('landing.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            if user.status != 'active':
                flash('Your account has been suspended. Contact support.', 'danger')
                return render_template('auth/login.html')

            session['user_id'] = user.id
            session['user_name'] = user.name
            session['user_email'] = user.email
            session['role'] = user.role

            flash(f'Welcome back, {user.name}!', 'success')
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        else:
            flash('Invalid email address or password.', 'danger')

    return render_template('auth/login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('index'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not name or not email or not password:
            flash('Please fill in all required fields.', 'danger')
            return render_template('auth/register.html')

        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return render_template('auth/register.html')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('An account with this email address already exists.', 'warning')
            return render_template('auth/register.html')

        new_user = User(
            name=name,
            email=email,
            phone=phone,
            password_hash=generate_password_hash(password),
            role='user',
            status='active'
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! Please log in with your credentials.', 'success')
        return redirect(url_for('login'))

    return render_template('auth/register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

# =========================================================================
# PUBLIC COMPLAINT TRACKING
# =========================================================================
@app.route('/track')
def track_complaint_public():
    complaint_id = request.args.get('complaint_id', '').strip().upper()
    complaint = None
    searched = False

    if complaint_id:
        searched = True
        complaint = Complaint.query.filter_by(complaint_id=complaint_id).first()

    return render_template('track_complaint.html', 
                           searched=searched, 
                           searched_id=complaint_id, 
                           complaint=complaint, 
                           active_page='track_complaint')

# =========================================================================
# USER ROUTES
# =========================================================================
@app.route('/dashboard')
@login_required
def user_dashboard():
    user_id = session['user_id']
    complaints = Complaint.query.filter_by(user_id=user_id).order_by(Complaint.created_at.desc()).all()

    stats = {
        'total': len(complaints),
        'pending': sum(1 for c in complaints if c.status == 'PENDING'),
        'under_review': sum(1 for c in complaints if c.status == 'UNDER_REVIEW'),
        'resolved': sum(1 for c in complaints if c.status == 'RESOLVED'),
    }

    recent_complaints = complaints[:5]

    return render_template('user/dashboard.html', 
                           stats=stats, 
                           recent_complaints=recent_complaints, 
                           active_page='user_dashboard')

@app.route('/my-complaints')
@login_required
def my_complaints():
    user_id = session['user_id']
    selected_status = request.args.get('status', '').strip()

    query = Complaint.query.filter_by(user_id=user_id)
    if selected_status:
        query = query.filter_by(status=selected_status)

    complaints = query.order_by(Complaint.created_at.desc()).all()

    return render_template('user/my_complaints.html', 
                           complaints=complaints, 
                           selected_status=selected_status, 
                           active_page='my_complaints')

@app.route('/submit-complaint', methods=['GET', 'POST'])
@login_required
def submit_complaint():
    if request.method == 'POST':
        # Section 1: Complaint Info
        title = request.form.get('title', '').strip()
        category = request.form.get('category', '').strip()
        description = request.form.get('description', '').strip()

        # Section 2: Incident Details
        incident_date = request.form.get('incident_date', '').strip()
        incident_time = request.form.get('incident_time', '').strip()
        amount_lost_raw = request.form.get('amount_lost', '0')
        try:
            amount_lost = float(amount_lost_raw)
        except ValueError:
            amount_lost = 0.0
        payment_method = request.form.get('payment_method', '').strip()

        # Section 3: Suspicious Info
        phone_number = request.form.get('phone_number', '').strip()
        email_addr = request.form.get('email', '').strip()
        upi_id = request.form.get('upi_id', '').strip()
        website_url = request.form.get('website_url', '').strip()
        social_media_account = request.form.get('social_media_account', '').strip()

        # Section 4: Evidence
        additional_info = request.form.get('additional_info', '').strip()
        evidence_file = request.files.get('evidence')
        
        evidence_filename = None
        evidence_original_name = None

        if evidence_file and evidence_file.filename:
            if allowed_file(evidence_file.filename):
                filename = secure_filename(evidence_file.filename)
                # Timestamped filename to avoid collisions
                unique_name = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                evidence_file.save(file_path)
                evidence_filename = unique_name
                evidence_original_name = filename
            else:
                flash('Invalid file format. Allowed: PNG, JPG, PDF, DOC, DOCX.', 'danger')
                return render_template('user/submit_complaint.html', active_page='submit_complaint')

        # Generate Complaint ID
        cid = generate_complaint_id(db)

        complaint_dict = {
            'category': category,
            'amount_lost': amount_lost,
            'payment_method': payment_method,
            'phone_number': phone_number,
            'email': email_addr,
            'upi_id': upi_id,
            'website_url': website_url,
            'evidence_filename': evidence_filename
        }

        # Check cross-database repeat counts for indicators
        indicator_counts = get_indicator_counts(complaint_dict)
        # Calculate Risk Assessment
        score, risk_lvl, reasons = evaluate_fraud_risk(complaint_dict, indicator_counts=indicator_counts)

        complaint = Complaint(
            complaint_id=cid,
            user_id=session['user_id'],
            title=title,
            category=category,
            description=description,
            incident_date=incident_date,
            incident_time=incident_time,
            amount_lost=amount_lost,
            payment_method=payment_method,
            phone_number=phone_number,
            email=email_addr,
            upi_id=upi_id,
            website_url=website_url,
            social_media_account=social_media_account,
            evidence_filename=evidence_filename,
            evidence_original_name=evidence_original_name,
            additional_info=additional_info,
            risk_score=score,
            risk_level=risk_lvl,
            status='PENDING'
        )
        complaint.risk_reasons = reasons

        db.session.add(complaint)
        db.session.flush()

        # Add initial timeline log
        history = ComplaintHistory(
            complaint_id=complaint.id,
            status='PENDING',
            remarks='Complaint submitted by user.',
            updated_by_name=session.get('user_name', 'User')
        )
        db.session.add(history)
        db.session.commit()

        # Re-evaluate all complaints in database to update repeat counts & risk scores
        all_c = Complaint.query.all()
        for c in all_c:
            cd = {
                'category': c.category,
                'amount_lost': c.amount_lost,
                'payment_method': c.payment_method,
                'phone_number': c.phone_number,
                'upi_id': c.upi_id,
                'website_url': c.website_url,
                'email': c.email,
                'evidence_filename': c.evidence_filename
            }
            ic = get_indicator_counts(cd)
            sc, r_lvl, r_reasons = evaluate_fraud_risk(cd, indicator_counts=ic)
            c.risk_score = sc
            c.risk_level = r_lvl
            c.risk_reasons = r_reasons
        db.session.commit()

        return redirect(url_for('submission_success', complaint_id=cid))

    return render_template('user/submit_complaint.html', active_page='submit_complaint')

@app.route('/complaint/success/<complaint_id>')
@login_required
def submission_success(complaint_id):
    complaint = Complaint.query.filter_by(complaint_id=complaint_id).first_or_404()
    if complaint.user_id != session['user_id'] and session.get('role') != 'admin':
        flash('Access denied.', 'danger')
        return redirect(url_for('user_dashboard'))
    return render_template('user/submission_success.html', complaint=complaint)

@app.route('/complaint/<complaint_id>')
@login_required
def view_complaint(complaint_id):
    complaint = Complaint.query.filter_by(complaint_id=complaint_id).first_or_404()

    # Security check: User can only view their own complaint unless Admin
    if complaint.user_id != session['user_id'] and session.get('role') != 'admin':
        flash('Access denied. You can only view your own complaints.', 'danger')
        return redirect(url_for('user_dashboard'))

    related_complaints = get_related_complaints(complaint)

    return render_template('complaint_detail.html', 
                           complaint=complaint, 
                           related_complaints=related_complaints, 
                           active_page='my_complaints' if session.get('role') != 'admin' else 'admin_complaints')

@app.route('/download-evidence/<filename>')
@login_required
def download_evidence(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not check_password_hash(user.password_hash, current_password):
            flash('Current password is incorrect.', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
        elif len(new_password) < 6:
            flash('New password must be at least 6 characters.', 'warning')
        else:
            user.password_hash = generate_password_hash(new_password)
            db.session.commit()
            flash('Password updated successfully!', 'success')

    return render_template('user/profile.html', user=user, active_page='profile')

# =========================================================================
# ADMIN ROUTES
# =========================================================================
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    complaints = Complaint.query.all()

    stats = {
        'total': len(complaints),
        'pending': sum(1 for c in complaints if c.status == 'PENDING'),
        'under_review': sum(1 for c in complaints if c.status == 'UNDER_REVIEW'),
        'investigating': sum(1 for c in complaints if c.status == 'INVESTIGATING'),
        'resolved': sum(1 for c in complaints if c.status == 'RESOLVED'),
        'high_risk': sum(1 for c in complaints if c.risk_level in ['HIGH', 'CRITICAL'])
    }

    recent_complaints = Complaint.query.order_by(Complaint.created_at.desc()).limit(6).all()

    return render_template('admin/dashboard.html', 
                           stats=stats, 
                           recent_complaints=recent_complaints, 
                           active_page='admin_dashboard')

@app.route('/admin/complaints')
@admin_required
def admin_complaints():
    query_str = request.args.get('q', '').strip()
    category = request.args.get('category', '').strip()
    status = request.args.get('status', '').strip()
    risk = request.args.get('risk', '').strip()

    q = Complaint.query

    if query_str:
        search_fmt = f"%{query_str}%"
        q = q.filter(
            (Complaint.complaint_id.like(search_fmt)) |
            (Complaint.title.like(search_fmt)) |
            (Complaint.phone_number.like(search_fmt)) |
            (Complaint.upi_id.like(search_fmt)) |
            (Complaint.website_url.like(search_fmt))
        )

    if category:
        q = q.filter(Complaint.category == category)
    if status:
        q = q.filter(Complaint.status == status)
    if risk:
        q = q.filter(Complaint.risk_level == risk)

    complaints = q.order_by(Complaint.created_at.desc()).all()

    return render_template('admin/all_complaints.html', 
                           complaints=complaints, 
                           query=query_str, 
                           selected_category=category, 
                           selected_status=status, 
                           selected_risk=risk, 
                           active_page='admin_complaints')

@app.route('/admin/complaint/<complaint_id>/update', methods=['POST'])
@admin_required
def update_complaint_status(complaint_id):
    complaint = Complaint.query.filter_by(complaint_id=complaint_id).first_or_404()
    
    new_status = request.form.get('status', '').strip()
    remarks = request.form.get('admin_remarks', '').strip()

    if new_status and new_status in ['PENDING', 'UNDER_REVIEW', 'INVESTIGATING', 'RESOLVED', 'REJECTED']:
        old_status = complaint.status
        complaint.status = new_status
        complaint.admin_remarks = remarks
        complaint.updated_at = datetime.utcnow()

        history = ComplaintHistory(
            complaint_id=complaint.id,
            status=new_status,
            remarks=remarks or f'Status updated from {old_status} to {new_status}',
            updated_by_name=session.get('user_name', 'Admin')
        )
        db.session.add(history)
        db.session.commit()

        flash(f'Complaint {complaint_id} status updated to {new_status}.', 'success')
    else:
        flash('Invalid status provided.', 'danger')

    return redirect(url_for('view_complaint', complaint_id=complaint_id))

@app.route('/admin/analytics')
@admin_required
def admin_analytics():
    return render_template('admin/analytics.html', active_page='admin_analytics')

@app.route('/admin/users')
@admin_required
def admin_users():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin/users.html', users=users, active_page='admin_users')

# =========================================================================
# JSON API FOR CHART.JS ANALYTICS
# =========================================================================
@app.route('/api/analytics-data')
@login_required
def api_analytics_data():
    complaints = Complaint.query.all()

    # 1. Categories
    category_counts = {}
    for c in complaints:
        category_counts[c.category] = category_counts.get(c.category, 0) + 1

    # 2. Statuses
    status_order = ['PENDING', 'UNDER_REVIEW', 'INVESTIGATING', 'RESOLVED', 'REJECTED']
    status_counts = {s: 0 for s in status_order}
    for c in complaints:
        if c.status in status_counts:
            status_counts[c.status] += 1

    # 3. Risk Levels
    risk_order = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    risk_counts = {r: 0 for r in risk_order}
    for c in complaints:
        if c.risk_level in risk_counts:
            risk_counts[c.risk_level] += 1

    # 4. Trend (Last 6 Months / Days)
    today = datetime.now()
    months_labels = []
    months_counts = []
    
    for i in range(5, -1, -1):
        m_date = today - timedelta(days=i*30)
        m_str = m_date.strftime('%b %Y')
        months_labels.append(m_str)
        
        # Count complaints created in that month
        cnt = sum(1 for c in complaints if c.created_at.year == m_date.year and c.created_at.month == m_date.month)
        months_counts.append(cnt)

    return jsonify({
        'categories': {
            'labels': list(category_counts.keys()),
            'data': list(category_counts.values())
        },
        'statuses': {
            'labels': [s.replace('_', ' ') for s in status_order],
            'data': [status_counts[s] for s in status_order]
        },
        'risk_levels': {
            'labels': risk_order,
            'data': [risk_counts[r] for r in risk_order]
        },
        'trend': {
            'labels': months_labels,
            'data': months_counts
        }
    })

# =========================================================================
# ERROR HANDLERS
# =========================================================================
@app.errorhandler(404)
def page_not_found(e):
    return render_template('landing.html'), 404

@app.errorhandler(500)
def server_error(e):
    return "<h3>Something went wrong. Please try again.</h3>", 500

_initialized = False

@app.before_request
def initialize_database_once():
    global _initialized
    if not _initialized:
        _initialized = True
        try:
            db.create_all()
            seed_initial_data(db)
        except Exception as e:
            print(f"[Init Warning] Could not seed database: {e}")

if __name__ == '__main__':
    print("[Anti-Scam Portal] Starting local server at http://127.0.0.1:5000 ...")
    app.run(host='127.0.0.1', port=5000, debug=True)
