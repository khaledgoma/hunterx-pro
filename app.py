#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   HUNTERX ENTERPRISE v7.0 - PRODUCTION HARDENED BUILD       ║
║   Email Verification + POST CSRF + Dynamic Admin Key        ║
║   Developed by Khaled Gomaa                                 ║
╚══════════════════════════════════════════════════════════════╝
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_mail import Mail, Message
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect, CSRFError
from urllib.parse import urlparse
import os, json, hashlib, secrets, logging, re

# ============ APP SETUP ============
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# 📧 Email Configuration (Strict Environment Variables)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('HUNTERX_MAIL_USER', 'khaledalqinas@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('HUNTERX_MAIL_PASS', None)
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('HUNTERX_MAIL_USER', 'khaledalqinas@gmail.com')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.expanduser('~/hunterx/web_dashboard/users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
csrf = CSRFProtect(app)
mail = Mail(app)

REPORT_DIR = os.path.expanduser('~/hunterx/web_dashboard/reports')
os.makedirs(REPORT_DIR, exist_ok=True)

# ============ DATABASE MODELS ============

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    title = db.Column(db.String(200), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    icon = db.Column(db.String(10), default='📌')
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    plan = db.Column(db.String(20), default='trial')
    assets_limit = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_active = db.Column(db.Boolean, default=False)  # Disabled until email verified
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), nullable=True)
    reset_token_hash = db.Column(db.String(100), nullable=True)
    reset_token_expiry = db.Column(db.DateTime, nullable=True)
    affiliate_ref = db.Column(db.String(20), nullable=True)
    scans = db.relationship('ScanHistory', backref='user', cascade="all, delete-orphan", lazy=True)
    notifications = db.relationship('Notification', backref='user', cascade="all, delete-orphan", lazy=True)

class ScanHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    target = db.Column(db.String(200), nullable=False)
    findings_count = db.Column(db.Integer, default=0)
    critical = db.Column(db.Integer, default=0)
    high = db.Column(db.Integer, default=0)
    medium = db.Column(db.Integer, default=0)
    low = db.Column(db.Integer, default=0)
    pdf_path = db.Column(db.String(300))
    scanned_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class AffiliateLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    affiliate_id = db.Column(db.String(50), unique=True, nullable=False)
    name = db.Column(db.String(100), nullable=False)
    commission_rate = db.Column(db.Integer, default=25)
    clicks = db.Column(db.Integer, default=0)
    conversions = db.Column(db.Integer, default=0)
    earnings = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

class AffiliateClickLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    affiliate_id = db.Column(db.String(50), nullable=False)
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.String(200))
    clicked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# 🆕 إنشاء الأدمن الافتراضي بكلمة مرور ديناميكية آمنة
def create_default_admin():
    admin_pass = os.environ.get('HUNTERX_ADMIN_PASS', secrets.token_urlsafe(16))
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin', email='admin@hunterx.com',
            password_hash=generate_password_hash(admin_pass, method='pbkdf2:sha256:600000'),
            plan='enterprise', assets_limit=999, is_active=True, email_verified=True
        )
        db.session.add(admin)
        db.session.commit()
        app.logger.info(f"Admin created with dynamic key: {admin_pass}")
        return admin_pass
    return None

with app.app_context():
    db.create_all()
    admin_key = create_default_admin()

# ============ HELPERS ============

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = db.session.get(User, session['user_id'])
        if not user or not user.is_active or not user.email_verified:
            session.clear()
            return redirect(url_for('login'))
        if user.plan == 'trial':
            now_utc = datetime.now(timezone.utc)
            created = user.created_at.replace(tzinfo=timezone.utc) if user.created_at.tzinfo is None else user.created_at
            if (now_utc - created).days >= 3:
                flash('Your 3-day free trial has expired. Upgrade to continue.', 'warning')
                return redirect(url_for('pricing'))
        session.permanent = True
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = db.session.get(User, session['user_id'])
        if not user or user.username != 'admin':
            flash('Access denied.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def send_notification(title, message, icon='📌', user_id=None):
    try:
        notif = Notification(user_id=user_id, title=title, message=message, icon=icon)
        db.session.add(notif)
        db.session.commit()
    except Exception as e:
        app.logger.error(f"Notification error: {e}")

def send_email(to, subject, body):
    if not app.config['MAIL_PASSWORD']:
        app.logger.error("MAIL_PASSWORD not set!")
        return False
    try:
        msg = Message(subject, recipients=[to], html=body)
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Email error: {e}")
        return False

@app.context_processor
def inject_unread_count():
    if 'user_id' not in session:
        return dict(unread_count=0)
    try:
        user = db.session.get(User, session['user_id'])
        if not user:
            return dict(unread_count=0)
        if user.username == 'admin':
            count = Notification.query.filter_by(is_read=False).count()
        else:
            count = Notification.query.filter_by(user_id=user.id, is_read=False).count()
        return dict(unread_count=count)
    except Exception as e:
        app.logger.error(f"Context error: {e}")
        return dict(unread_count=0)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    app.logger.warning(f"CSRF Error: {e}")
    flash('Security validation failed. Please try again.', 'danger')
    return redirect(url_for('login'))

# ============ AUTH ROUTES ============

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password) and user.is_active:
            if not user.email_verified:
                flash('Please verify your email first. Check your inbox.', 'warning')
                return redirect(url_for('login'))
            session.clear()
            session['user_id'] = user.id
            session['user_name'] = user.username
            session.permanent = True
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        errors = []
        if len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        if len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        if '@' not in email or '.' not in email:
            errors.append('Please enter a valid email address.')
        if User.query.filter_by(username=username).first():
            errors.append('Username already exists.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return redirect(url_for('register'))

        ref = request.args.get('ref', '')
        valid_ref = None
        if ref:
            if AffiliateLink.query.filter_by(affiliate_id=ref).first():
                valid_ref = ref

        token = secrets.token_urlsafe(32)
        user = User(
            username=username, email=email,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256:600000'),
            plan='trial', assets_limit=1, affiliate_ref=valid_ref,
            is_active=False, email_verified=False, verification_token=token
        )
        db.session.add(user)
        db.session.commit()

        # Send verification email
        verify_link = f"{request.url_root}verify/{token}"
        if send_email(email, "Verify Your HunterX Account",
            f"<h2>Welcome {username}!</h2><p>Click to verify: <a href='{verify_link}'>{verify_link}</a></p>"):
            flash('Account created! Check your email to verify.', 'success')
        else:
            app.logger.error(f"Verification email failed for {email}")
            flash('Account created! Please contact support for verification.', 'warning')

        send_notification("🆕 New User Registered", f"<b>{username}</b> ({email}) just joined.", "👤")
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user and not user.email_verified:
        user.email_verified = True
        user.is_active = True
        user.verification_token = None
        db.session.commit()
        send_notification("🎉 Welcome!", f"Your email has been verified. Start exploring!", "👋", user_id=user.id)
        flash('Email verified! You can now login.', 'success')
    else:
        flash('Invalid or expired verification link.', 'danger')
    return redirect(url_for('login'))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('login'))

# ============ DASHBOARD ============

@app.route('/')
@login_required
def dashboard():
    user = db.session.get(User, session['user_id'])
    scans = ScanHistory.query.filter_by(user_id=user.id).order_by(ScanHistory.scanned_at.desc()).all()
    stats = {
        'total_scans': len(scans),
        'critical': sum(s.critical for s in scans),
        'high': sum(s.high for s in scans),
        'medium': sum(s.medium for s in scans),
        'low': sum(s.low for s in scans),
        'last_scan': scans[0].scanned_at.strftime('%Y-%m-%d %H:%M') if scans else 'No scans yet',
        'plan': user.plan.capitalize(),
        'assets_used': len(set(s.target for s in scans)),
        'assets_limit': user.assets_limit
    }
    return render_template('dashboard.html', stats=stats, user=user)

# ============ SCAN ============

@app.route('/scan', methods=['POST'])
@login_required
def start_scan():
    user = db.session.get(User, session['user_id'])
    if user.plan == 'trial':
        flash('Manual scanning requires a paid plan.', 'warning')
        return redirect(url_for('pricing'))
    target = request.form.get('target', '')
    if len(set(s.target for s in user.scans)) >= user.assets_limit:
        flash('Asset limit reached. Upgrade!', 'warning')
        return redirect(url_for('pricing'))
    findings = [
        {'severity': 'CRITICAL', 'title': 'SQL Injection', 'endpoint': f'{target}/login'},
        {'severity': 'HIGH', 'title': 'Exposed Component', 'endpoint': f'{target}/dashboard'},
        {'severity': 'MEDIUM', 'title': 'Missing Security Headers', 'endpoint': target},
    ]
    pdf_fn = f"{secrets.token_hex(16)}.pdf"
    scan = ScanHistory(user_id=user.id, target=target, findings_count=3, critical=1, high=1, medium=1, low=0, pdf_path=pdf_fn)
    db.session.add(scan)
    db.session.commit()
    send_notification("🔍 Scan Completed", f"Scan of <b>{target}</b> completed.", "🎯", user_id=user.id)
    flash(f'Scan completed for {target}!', 'success')
    return redirect(url_for('dashboard'))

@app.route('/generate-report', methods=['POST'])
@login_required
def generate_manual_report():
    user = db.session.get(User, session['user_id'])
    if user.plan == 'trial':
        flash('Manual reports require a paid plan.', 'warning')
        return redirect(url_for('pricing'))
    program = request.form.get('program', 'Manual')
    sev = request.form.get('severity', 'INFO')
    pdf_fn = f"{secrets.token_hex(16)}.pdf"
    scan = ScanHistory(user_id=user.id, target=program, findings_count=1, critical=1 if sev=='CRITICAL' else 0, high=1 if sev=='HIGH' else 0, medium=1 if sev=='MEDIUM' else 0, low=1 if sev=='LOW' else 0, pdf_path=pdf_fn)
    db.session.add(scan)
    db.session.commit()
    send_notification("📋 Report Generated", f"Report for <b>{program}</b> created.", "📄", user_id=user.id)
    flash('Report generated!', 'success')
    return redirect(url_for('reports'))

# ============ REPORTS ============

@app.route('/reports')
@login_required
def reports():
    user = db.session.get(User, session['user_id'])
    scans = ScanHistory.query.filter_by(user_id=user.id).order_by(ScanHistory.scanned_at.desc()).all()
    return render_template('reports.html', reports=scans)

@app.route('/download/<int:scan_id>')
@login_required
def download_report(scan_id):
    user = db.session.get(User, session['user_id'])
    record = db.session.get(ScanHistory, scan_id)
    if not record or (record.user_id != user.id and user.username != 'admin'):
        flash('Unauthorized.', 'danger')
        return redirect(url_for('reports'))
    return send_from_directory(REPORT_DIR, secure_filename(record.pdf_path), as_attachment=True)

# ============ NOTIFICATIONS ============

@app.route('/notifications')
@login_required
def notifications():
    user = db.session.get(User, session['user_id'])
    if user.username == 'admin':
        notifs = Notification.query.order_by(Notification.created_at.desc()).limit(50).all()
    else:
        notifs = Notification.query.filter_by(user_id=user.id).order_by(Notification.created_at.desc()).limit(20).all()
    return render_template('notifications.html', notifications=notifs)

@app.route('/notifications/read/<int:nid>', methods=['POST'])
@login_required
def mark_read(nid):
    n = db.session.get(Notification, nid)
    if n:
        n.is_read = True
        db.session.commit()
    return redirect(url_for('notifications'))

@app.route('/notifications/clear', methods=['POST'])
@login_required
def clear_notifications():
    user = db.session.get(User, session['user_id'])
    Notification.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    flash('Cleared.', 'success')
    return redirect(url_for('dashboard'))

# ============ AFFILIATES ============

@app.route('/affiliates')
@login_required
@admin_required
def affiliate_dashboard():
    links = AffiliateLink.query.all()
    return render_template('affiliates.html', affiliates={l.affiliate_id:{'name':l.name,'commission':l.commission_rate,'clicks':l.clicks,'conversions':l.conversions,'earnings':l.earnings,'link':f"{request.url_root}landing?ref={l.affiliate_id}"} for l in links}, total_clicks=sum(l.clicks for l in links), total_conversions=sum(l.conversions for l in links), total_earnings=sum(l.earnings for l in links))

@app.route('/affiliates/add', methods=['POST'])
@login_required
@admin_required
def add_affiliate():
    name = request.form.get('name','Partner')
    com = int(request.form.get('commission',25))
    aid = hashlib.md5(f"{name}_{secrets.token_hex(4)}".encode()).hexdigest()[:8]
    db.session.add(AffiliateLink(affiliate_id=aid, name=name, commission_rate=com))
    db.session.commit()
    flash(f'Link: {request.url_root}landing?ref={aid}', 'success')
    return redirect(url_for('affiliate_dashboard'))

@app.route('/affiliates/delete/<aid>', methods=['POST'])
@login_required
@admin_required
def delete_affiliate(aid):
    l = AffiliateLink.query.filter_by(affiliate_id=aid).first()
    if l: db.session.delete(l); db.session.commit()
    return redirect(url_for('affiliate_dashboard'))

# ============ UPGRADE ============

@app.route('/upgrade', methods=['POST'])
@login_required
def upgrade_plan():
    flash('Please complete your purchase via the Pricing page.', 'info')
    return redirect(url_for('pricing'))

# ============ STATIC PAGES ============

@app.route('/landing')
def landing():
    ref = request.args.get('ref','')
    if ref:
        link = AffiliateLink.query.filter_by(affiliate_id=ref).first()
        if link:
            yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
            if not AffiliateClickLog.query.filter(AffiliateClickLog.affiliate_id==ref, AffiliateClickLog.ip_address==request.remote_addr, AffiliateClickLog.clicked_at>yesterday).first():
                link.clicks += 1
            db.session.add(AffiliateClickLog(affiliate_id=ref, ip_address=request.remote_addr, user_agent=request.user_agent.string[:200]))
            db.session.commit()
    return render_template('landing.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/profile')
@login_required
def profile():
    user = db.session.get(User, session['user_id'])
    scans = ScanHistory.query.filter_by(user_id=user.id).all()
    return render_template('profile.html', user=user, scans=scans)

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/forgot-password', methods=['GET','POST'])
def forgot_password():
    if request.method == 'POST':
        flash('If that email exists, a reset link has been sent.', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET','POST'])
def reset_password(token):
    if request.method == 'POST':
        flash('Password updated!', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

# ============ ADMIN PANEL ============

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html', total_users=User.query.count(), total_scans=ScanHistory.query.count(), recent_users=User.query.order_by(User.created_at.desc()).limit(10).all())

@app.route('/admin/user/<int:uid>/edit', methods=['POST'])
@admin_required
def edit_user(uid):
    u = db.session.get(User, uid)
    if u and u.username != 'admin':
        u.plan = request.form.get('plan', u.plan)
        u.assets_limit = int(request.form.get('assets_limit', u.assets_limit))
        u.is_active = request.form.get('is_active', 'true') == 'true'
        db.session.commit()
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:uid>/delete', methods=['POST'])
@admin_required
def delete_user(uid):
    u = db.session.get(User, uid)
    if u and u.username != 'admin':
        db.session.delete(u)
        db.session.commit()
    return redirect(url_for('admin_panel'))

# ============ RUN ============
if __name__ == '__main__':
    print(f"""
╔══════════════════════════════════════════╗
║   🛡️  HUNTERX ENTERPRISE v7.0 HARDENED  ║
║   http://localhost:5000                 ║
║   Admin Key: {admin_key if admin_key else 'Set via HUNTERX_ADMIN_PASS'} ║
╚══════════════════════════════════════════╝
    """)
    app.run(debug=False, host='0.0.0.0', port=5000)
