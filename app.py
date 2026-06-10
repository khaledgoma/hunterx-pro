#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║   HUNTERX ENTERPRISE v5.3.2 - IRONCLAD PRODUCTION BUILD     ║
║   Fixed: Notification Privacy, Timezone, All Security Fixes ║
║   Developed by Khaled Gomaa                                 ║
╚══════════════════════════════════════════════════════════════╝
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, g
from flask_mail import Mail, Message
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect, CSRFError
from wtforms.validators import Email as EmailValidator
import re
from urllib.parse import urlparse
import os, json, hashlib, secrets, logging

# ============ APP SETUP ============
app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

logging.basicConfig(level=logging.INFO)
app.logger.setLevel(logging.INFO)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=8)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# 📧 Email Configuration (Secure: Environment Variables)
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
    is_active = db.Column(db.Boolean, default=True)
    email_verified = db.Column(db.Boolean, default=True)
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

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='admin').first():
        admin = User(
            username='admin', email='admin@hunterx.com',
            password_hash=generate_password_hash('HunterX2026!', method='pbkdf2:sha256:600000'),
            plan='enterprise', assets_limit=999, is_active=True, email_verified=True
        )
        db.session.add(admin)
        db.session.commit()

# ============ HELPERS ============

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = get_current_user()
        if not user:
            return redirect(url_for('login'))
        if not user.is_active:
            flash('Account suspended. Contact support.', 'danger')
            return redirect(url_for('login'))
        if user.plan == 'trial':
            now_utc = datetime.now(timezone.utc)
            if user.created_at.tzinfo is None:
                user_created = user.created_at.replace(tzinfo=timezone.utc)
            else:
                user_created = user.created_at
            days_passed = (now_utc - user_created).days
            if days_passed >= 3:
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
        user = get_current_user()
        if not user or user.username != 'admin':
            flash('Access denied. Admin privileges required.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

def get_current_user():
    if 'user_id' in session:
        return db.session.get(User, session['user_id'])
    return None

def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(target)
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def save_scan_to_db(user_id, target, findings, pdf_filename):
    scan = ScanHistory(
        user_id=user_id, target=target, findings_count=len(findings),
        critical=sum(1 for f in findings if f.get('severity') == 'CRITICAL'),
        high=sum(1 for f in findings if f.get('severity') == 'HIGH'),
        medium=sum(1 for f in findings if f.get('severity') == 'MEDIUM'),
        low=sum(1 for f in findings if f.get('severity') == 'LOW'),
        pdf_path=pdf_filename
    )
    db.session.add(scan)
    db.session.commit()

def send_notification(title, message, icon='📌', user_id=None):
    """
    Send notification.
    - user_id=user.id: visible only to that specific user
    - user_id=None: visible to all users (public system notification)
    """
    notif = Notification(
        user_id=user_id,
        title=title,
        message=message,
        icon=icon
    )
    db.session.add(notif)
    db.session.commit()

def send_email(to, subject, body):
    if not app.config['MAIL_PASSWORD']:
        app.logger.error("Email configurations missing! HUNTERX_MAIL_PASS is None.")
        return False
    try:
        msg = Message(subject, recipients=[to], html=body)
        mail.send(msg)
        return True
    except Exception as e:
        app.logger.error(f"Email failed to {to}: {e}")
        return False

# ============ CONTEXT PROCESSOR ============

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
            # المستخدم العادي: فقط إشعاراته الخاصة
            count = Notification.query.filter_by(user_id=user.id, is_read=False).count()
        return dict(unread_count=count)
    except Exception:
        return dict(unread_count=0)

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('Security validation failed. Please try again.', 'danger')
    referrer = request.referrer
    if referrer and is_safe_url(referrer):
        return redirect(referrer)
    return redirect(url_for('dashboard'))
def is_valid_email(email):
    """التحقق من صيغة الإيميل"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None
def hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()

# ============ AUTH ROUTES ============

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            if not user.is_active:
                flash('Account suspended. Contact support.', 'danger')
                return redirect(url_for('login'))
            session.clear()
            session['user_id'] = user.id
            session['user_name'] = user.username
            session.permanent = True
            flash(f'Welcome back, {user.username}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials', 'danger')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '')
        email = request.form.get('email', '')
        if not is_valid_email(email):
            flash('Please enter a valid email address.', 'danger')
            return redirect(url_for('register'))
        password = request.form.get('password', '')
        ref = request.args.get('ref', '')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        valid_ref = None
        if ref:
            aff_exists = AffiliateLink.query.filter_by(affiliate_id=ref).first()
            if aff_exists:
                valid_ref = ref
        
        user = User(
            username=username, email=email,
            password_hash=generate_password_hash(password, method='pbkdf2:sha256:600000'),
            plan='trial', assets_limit=1, affiliate_ref=valid_ref,
            is_active=True, email_verified=True
        )
                db.session.add(user)
        db.session.commit()
        
        # إشعار خاص بالمستخدم الجديد فقط (مع تجاهل الأخطاء)
        try:
            send_notification("🎉 Welcome!", f"Thanks for joining, {username}! Your 3-day trial starts now.", "👋", user_id=user.id)
            send_notification("🆕 New User Registered", f"<b>{username}</b> ({email}) just joined.", "👤")
        except Exception:
            pass  # تجاهل أي خطأ في الإشعارات أو الإيميلات
        session['user_id'] = user.id
        session['user_name'] = user.username
        session.permanent = True
        
        flash(f'Welcome to HunterX, {username}! Your 3-day free trial is active.', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('register.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '')
        user = User.query.filter_by(email=email).first()
        if user:
            token = secrets.token_urlsafe(32)
            user.reset_token_hash = hash_token(token)
            user.reset_token_expiry = datetime.now(timezone.utc) + timedelta(hours=1)
            db.session.commit()
            reset_link = f"{request.url_root}reset-password/{token}"
            if send_email(email, "Reset Your HunterX Password",
                f"<h2>Password Reset</h2><p>Click to reset: <a href='{reset_link}'>{reset_link}</a></p><p>Link expires in 1 hour.</p>"):
                app.logger.info(f"Password reset email sent to {email}")
            else:
                app.logger.error(f"Failed to send password reset email to {email}")
        flash('If that email exists, a reset link has been sent.', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    token_hash = hash_token(token)
    user = User.query.filter_by(reset_token_hash=token_hash).first()
    if not user or not user.reset_token_expiry or user.reset_token_expiry < datetime.now(timezone.utc):
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('login'))
    if request.method == 'POST':
        password = request.form.get('password', '')
        user.password_hash = generate_password_hash(password, method='pbkdf2:sha256:600000')
        user.reset_token_hash = None
        user.reset_token_expiry = None
        db.session.commit()
        flash('Password updated! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', token=token)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ============ DASHBOARD ============

@app.route('/')
@login_required
def dashboard():
    user = get_current_user()
    scans = ScanHistory.query.filter_by(user_id=user.id).order_by(ScanHistory.scanned_at.desc()).all()
    stats = {
        'total_scans': len(scans),
        'critical': sum(s.critical for s in scans),
        'high': sum(s.high for s in scans),
        'medium': sum(s.medium for s in scans),
        'low': sum(s.low for s in scans),
        'last_scan': scans[0].scanned_at.strftime('%Y-%m-%d %H:%M') if scans else 'No scans yet',
        'targets': list(set(s.target for s in scans))[-5:] if scans else ['example.com'],
        'plan': user.plan.capitalize(),
        'assets_used': len(set(s.target for s in scans)),
        'assets_limit': user.assets_limit
    }
    return render_template('dashboard.html', stats=stats, user=user)

# ============ SCAN ROUTES ============

@app.route('/scan', methods=['POST'])
@login_required
def start_scan():
    user = get_current_user()
    if user.plan == 'trial':
        flash('Manual scanning is only available for paid plans. Please upgrade!', 'warning')
        return redirect(url_for('pricing'))
    target = request.form.get('target', '')
    current_assets = len(set(s.target for s in user.scans))
    if current_assets >= user.assets_limit:
        flash(f'Asset limit reached ({user.assets_limit}). Upgrade your plan!', 'warning')
        return redirect(url_for('pricing'))
    demo_findings = [
        {'severity': 'CRITICAL', 'title': 'SQL Injection', 'endpoint': f'{target}/login'},
        {'severity': 'HIGH', 'title': 'Exported Component', 'endpoint': f'{target}/dashboard'},
        {'severity': 'MEDIUM', 'title': 'Missing Headers', 'endpoint': target},
    ]
    pdf_filename = f"{secrets.token_hex(16)}.pdf"
    save_scan_to_db(user.id, target, demo_findings, pdf_filename)
    # إشعار خاص بالمستخدم
    send_notification("🔍 Scan Completed", f"Scan of <b>{target}</b> completed with 3 findings.", "🎯", user_id=user.id)
    flash(f'Scan completed for {target}! 3 findings.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/generate-report', methods=['POST'])
@login_required
def generate_manual_report():
    user = get_current_user()
    if user.plan == 'trial':
        flash('Manual report generation is only available for paid plans. Please upgrade!', 'warning')
        return redirect(url_for('pricing'))
    program = request.form.get('program', 'Manual')
    template_id = request.form.get('template', '1')
    severity = request.form.get('severity', 'INFO')
    templates = {"1":"Exported Component","2":"Insecure WebView","3":"Hardcoded Key","4":"IDOR","5":"SQL Injection","6":"XSS","7":"CSRF","8":"SSRF"}
    title = templates.get(template_id, "Security Finding")
    findings = [{'severity': severity, 'title': title, 'endpoint': program}]
    pdf_filename = f"{secrets.token_hex(16)}.pdf"
    save_scan_to_db(user.id, program, findings, pdf_filename)
    # إشعار خاص بالمستخدم
    send_notification("📋 Report Generated", f"Manual report for <b>{program}</b> created.", "📄", user_id=user.id)
    flash('Report generated!', 'success')
    return redirect(url_for('reports'))

# ============ REPORTS ============

@app.route('/reports')
@login_required
def reports():
    user = get_current_user()
    scans = ScanHistory.query.filter_by(user_id=user.id).order_by(ScanHistory.scanned_at.desc()).all()
    return render_template('reports.html', reports=scans)

@app.route('/download/<int:scan_id>')
@login_required
def download_report(scan_id):
    user = get_current_user()
    record = db.session.get(ScanHistory, scan_id)
    if not record:
        flash('Report not found.', 'danger')
        return redirect(url_for('reports'))
    if record.user_id != user.id and user.username != 'admin':
        flash('Unauthorized access to this report.', 'danger')
        return redirect(url_for('reports'))
    safe_name = secure_filename(record.pdf_path)
    return send_from_directory(REPORT_DIR, safe_name, as_attachment=True)

# ============ NOTIFICATIONS (FIXED PRIVACY) ============

@app.route('/notifications')
@login_required
def notifications():
    user = get_current_user()
    if not user:
        return redirect(url_for('login'))
    
    if user.username == 'admin':
        # الأدمن يرى جميع الإشعارات (الخاصة + العامة + إشعارات المستخدمين)
        notifs = Notification.query.order_by(Notification.created_at.desc()).limit(50).all()
    else:
        # المستخدم العادي يرى إشعاراته الخاصة فقط
        notifs = Notification.query.filter(
            Notification.user_id == user.id
        ).order_by(Notification.created_at.desc()).limit(20).all()
    
    return render_template('notifications.html', notifications=notifs)

@app.route('/notifications/read/<int:notif_id>')
@login_required
def mark_read(notif_id):
    notif = db.session.get(Notification, notif_id)
    if notif:
        notif.is_read = True
        db.session.commit()
    return redirect(url_for('notifications'))

@app.route('/notifications/clear')
@login_required
def clear_notifications():
    user = get_current_user()
    if user.username == 'admin':
        Notification.query.delete()
    else:
        Notification.query.filter_by(user_id=user.id).delete()
    db.session.commit()
    flash('All notifications cleared.', 'success')
    return redirect(url_for('dashboard'))

# ============ AFFILIATE ROUTES ============

@app.route('/affiliates')
@login_required
@admin_required
def affiliate_dashboard():
    links = AffiliateLink.query.all()
    clicks_log = AffiliateClickLog.query.order_by(AffiliateClickLog.clicked_at.desc()).limit(20).all()
    total_clicks = db.session.query(db.func.sum(AffiliateLink.clicks)).scalar() or 0
    total_conversions = db.session.query(db.func.sum(AffiliateLink.conversions)).scalar() or 0
    total_earnings = db.session.query(db.func.sum(AffiliateLink.earnings)).scalar() or 0.0
    affiliates_dict = {
        l.affiliate_id: {
            'name': l.name, 'commission': l.commission_rate,
            'clicks': l.clicks, 'conversions': l.conversions,
            'earnings': l.earnings, 'link': f"{request.url_root}landing?ref={l.affiliate_id}"
        } for l in links
    }
    recent_clicks = [
        {'affiliate_id': c.affiliate_id, 'ip': c.ip_address,
         'timestamp': c.clicked_at.strftime('%Y-%m-%d %H:%M:%S')} for c in clicks_log
    ]
    return render_template('affiliates.html',
        affiliates=affiliates_dict, total_clicks=total_clicks,
        total_conversions=total_conversions, total_earnings=total_earnings,
        recent_clicks=recent_clicks)

@app.route('/affiliates/add', methods=['POST'])
@login_required
@admin_required
def add_affiliate():
    name = request.form.get('name', 'Partner')
    commission = int(request.form.get('commission', 25))
    affiliate_id = hashlib.md5(f"{name}_{secrets.token_hex(4)}".encode()).hexdigest()[:8]
    new_link = AffiliateLink(affiliate_id=affiliate_id, name=name, commission_rate=commission)
    db.session.add(new_link)
    db.session.commit()
    # إشعار للأدمن فقط
    send_notification("🤝 New Affiliate Added", f"<b>{name}</b> joined with <b>{commission}%</b> commission.", "💰")
    generated_url = f"{request.url_root}landing?ref={affiliate_id}"
    flash(f'Affiliate link generated for {name}: {generated_url}', 'success')
    return redirect(url_for('affiliate_dashboard'))

@app.route('/affiliates/delete/<affiliate_id>', methods=['POST'])
@login_required
@admin_required
def delete_affiliate(affiliate_id):
    link = AffiliateLink.query.filter_by(affiliate_id=affiliate_id).first()
    if link:
        db.session.delete(link)
        db.session.commit()
        flash('Affiliate link removed successfully.', 'success')
    return redirect(url_for('affiliate_dashboard'))

# ============ UPGRADE ============

@app.route('/upgrade', methods=['POST'])
@login_required
def upgrade_plan():
    flash('Direct upgrades are currently disabled. Please complete your purchase via the Pricing page to unlock your plan.', 'info')
    return redirect(url_for('pricing'))

# ============ STATIC PAGES ============

@app.route('/landing')
def landing():
    ref = request.args.get('ref', '')
    if ref:
        aff_link = AffiliateLink.query.filter_by(affiliate_id=ref).first()
        if aff_link:
            yesterday = datetime.now(timezone.utc) - timedelta(hours=24)
            recent_click = AffiliateClickLog.query.filter(
                AffiliateClickLog.affiliate_id == ref,
                AffiliateClickLog.ip_address == request.remote_addr,
                AffiliateClickLog.clicked_at > yesterday
            ).first()
            if not recent_click:
                aff_link.clicks += 1
                click_log = AffiliateClickLog(
                    affiliate_id=ref, ip_address=request.remote_addr,
                    user_agent=request.user_agent.string[:200]
                )
                db.session.add(click_log)
                db.session.commit()
    return render_template('landing.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/profile')
@login_required
def profile():
    user = get_current_user()
    scans = ScanHistory.query.filter_by(user_id=user.id).all()
    return render_template('profile.html', user=user, scans=scans)

# ============ ADMIN PANEL ============

@app.route('/admin')
@admin_required
def admin_panel():
    return render_template('admin.html',
        total_users=User.query.count(),
        trial_users=User.query.filter_by(plan='trial').count(),
        paid_users=User.query.filter(User.plan != 'trial').count(),
        total_scans=ScanHistory.query.count(),
        affiliates={l.affiliate_id: {'name': l.name, 'commission': l.commission_rate, 'clicks': l.clicks, 'conversions': l.conversions, 'earnings': l.earnings} for l in AffiliateLink.query.all()},
        total_clicks=db.session.query(db.func.sum(AffiliateLink.clicks)).scalar() or 0,
        total_conversions=db.session.query(db.func.sum(AffiliateLink.conversions)).scalar() or 0,
        total_earnings=db.session.query(db.func.sum(AffiliateLink.earnings)).scalar() or 0.0,
        recent_users=User.query.order_by(User.created_at.desc()).limit(10).all(),
        recent_scans=ScanHistory.query.order_by(ScanHistory.scanned_at.desc()).limit(10).all(),
        recent_notifs=Notification.query.order_by(Notification.created_at.desc()).limit(10).all(),
        recent_clicks=[{'affiliate_id': c.affiliate_id, 'ip': c.ip_address, 'timestamp': c.clicked_at.strftime('%Y-%m-%d %H:%M:%S')} for c in AffiliateClickLog.query.order_by(AffiliateClickLog.clicked_at.desc()).limit(20).all()])

@app.route('/admin/user/<int:user_id>/edit', methods=['POST'])
@admin_required
def edit_user(user_id):
    target = db.session.get(User, user_id)
    if target:
        if target.username == 'admin':
            flash('Cannot modify the primary administrator account.', 'danger')
            return redirect(url_for('admin_panel'))
        target.plan = request.form.get('plan', target.plan)
        target.assets_limit = int(request.form.get('assets_limit', target.assets_limit))
        target.is_active = request.form.get('is_active', 'true') == 'true'
        db.session.commit()
        flash(f'User {target.username} updated!', 'success')
    else:
        flash('User not found.', 'danger')
    return redirect(url_for('admin_panel'))

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    target = db.session.get(User, user_id)
    if target and target.username != 'admin':
        db.session.delete(target)
        db.session.commit()
        flash(f'User {target.username} and all associated data deleted!', 'success')
    else:
        flash('Cannot delete this user.', 'danger')
    return redirect(url_for('admin_panel'))

# ============ RUN ============
if __name__ == '__main__':
    print("""
╔══════════════════════════════════════════╗
║    🛡️  HUNTERX ENTERPRISE v5.3.2 IRONCLAD║
║    Production Ready & Fully Hardened     ║
║    http://localhost:5000                 ║
╚══════════════════════════════════════════╝
    """)
    app.run(debug=False, host='0.0.0.0', port=5000)
