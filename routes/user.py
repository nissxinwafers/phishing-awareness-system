from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models.database import db
from datetime import datetime
from models.models import User, UrlScan, Feedback, SentEmail
from scanner.url_scanner import analyze_url

user_bp = Blueprint('user', __name__)


# ── Auth guard ────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in to access that page.', 'warning')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated


def current_user():
    return User.query.get(session['user_id'])


# ── Home / landing page ───────────────────────────────────────────────────────
@user_bp.route('/')
def index():
    if session.get('user_id'):
        return redirect(url_for('user.dashboard'))
    return render_template('home.html')


# ── Dashboard ─────────────────────────────────────────────────────────────────
@user_bp.route('/dashboard')
@login_required
def dashboard():
    uid = session['user_id']

    total  = UrlScan.query.filter_by(user_id=uid).count()
    high   = UrlScan.query.filter_by(user_id=uid, result='High Risk').count()
    medium = UrlScan.query.filter_by(user_id=uid, result='Medium Risk').count()
    low    = UrlScan.query.filter_by(user_id=uid, result='Low Risk').count()

    recent = (
        UrlScan.query
        .filter_by(user_id=uid)
        .order_by(UrlScan.created_at.desc())
        .limit(5)
        .all()
    )

    return render_template(
        'user/dashboard.html',
        total=total, high=high, medium=medium, low=low,
        recent=recent,
    )


# ── URL Scanner ───────────────────────────────────────────────────────────────
@user_bp.route('/scanner', methods=['GET', 'POST'])
@login_required
def scanner():
    if request.method == 'POST':
        url = request.form.get('url', '').strip()

        if not url:
            flash('Please enter a URL to scan.', 'warning')
            return render_template('user/scanner.html')

        # Basic prefix normalisation
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        analysis = analyze_url(url)

        scan = UrlScan(
            user_id=session['user_id'],
            scanned_url=url,
            score=analysis['score'],
            result=analysis['result'],
            reasons='\n'.join(analysis['reasons']),
        )
        db.session.add(scan)
        db.session.commit()

        return redirect(url_for('user.result', scan_id=scan.id))

    return render_template('user/scanner.html')


# ── Scan result ───────────────────────────────────────────────────────────────
@user_bp.route('/result/<int:scan_id>')
@login_required
def result(scan_id):
    scan = UrlScan.query.get_or_404(scan_id)

    # Users may only view their own scans
    if scan.user_id != session['user_id']:
        flash('You do not have permission to view that scan.', 'danger')
        return redirect(url_for('user.history'))

    reasons = [r for r in scan.reasons.split('\n') if r] if scan.reasons else []

    return render_template('user/result.html', scan=scan, reasons=reasons)


# ── Scan history ──────────────────────────────────────────────────────────────
@user_bp.route('/history')
@login_required
def history():
    uid = session['user_id']

    page  = request.args.get('page', 1, type=int)
    scans = (
        UrlScan.query
        .filter_by(user_id=uid)
        .order_by(UrlScan.created_at.desc())
        .paginate(page=page, per_page=10, error_out=False)
    )

    return render_template('user/history.html', scans=scans)


# ── Feedback ──────────────────────────────────────────────────────────────────
@user_bp.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        rating  = request.form.get('rating', type=int)

        if not message:
            flash('Please write a message before submitting.', 'warning')
            return render_template('user/feedback.html')

        if not rating or not (1 <= rating <= 5):
            flash('Please select a rating between 1 and 5.', 'warning')
            return render_template('user/feedback.html')

        fb = Feedback(
            user_id=session['user_id'],
            message=message,
            rating=rating,
        )
        db.session.add(fb)
        db.session.commit()

        flash('Thank you for your feedback!', 'success')
        return redirect(url_for('user.dashboard'))

    return render_template('user/feedback.html')


# ── Profile ───────────────────────────────────────────────────────────────────
@user_bp.route('/profile')
@login_required
def profile():
    user  = current_user()
    total = UrlScan.query.filter_by(user_id=user.id).count()
    high  = UrlScan.query.filter_by(user_id=user.id, result='High Risk').count()

    return render_template('user/profile.html', user=user, total=total, high=high)


# ── Inbox (simulated phishing emails from admin) ──────────────────────────────
@user_bp.route('/inbox')
@login_required
def inbox():
    uid = session['user_id']
    emails = (
        SentEmail.query
        .filter_by(recipient_id=uid)
        .order_by(SentEmail.sent_at.desc())
        .all()
    )
    return render_template('user/inbox.html', emails=emails)


@user_bp.route('/inbox/<int:email_id>')
@login_required
def view_email(email_id):
    email = SentEmail.query.get_or_404(email_id)
    if email.recipient_id != session['user_id']:
        flash('You do not have permission to view that email.', 'danger')
        return redirect(url_for('user.inbox'))

    if email.read_at is None:
        email.read_at = datetime.utcnow()
        db.session.commit()

    return render_template('user/view_email.html', email=email, t=email.template)


@user_bp.route('/inbox/<int:email_id>/click')
@login_required
def email_click(email_id):
    email = SentEmail.query.get_or_404(email_id)
    if email.recipient_id != session['user_id']:
        flash('You do not have permission to access that email.', 'danger')
        return redirect(url_for('user.inbox'))

    if email.clicked_at is None:
        email.clicked_at = datetime.utcnow()
        db.session.commit()

    return render_template('user/email_clicked.html', email=email, t=email.template)


@user_bp.route('/inbox/<int:email_id>/report', methods=['POST'])
@login_required
def email_report(email_id):
    email = SentEmail.query.get_or_404(email_id)
    if email.recipient_id != session['user_id']:
        flash('You do not have permission to access that email.', 'danger')
        return redirect(url_for('user.inbox'))

    if email.reported_at is None:
        email.reported_at = datetime.utcnow()
        db.session.commit()

    flash('Nice catch! You reported this as phishing.', 'success')
    return redirect(url_for('user.inbox'))


# ── Simulated phishing pages (educational — no data saved) ────────────────────
@user_bp.route('/phishing/bank', methods=['GET', 'POST'])
@login_required
def phishing_bank():
    if request.method == 'POST':
        # Discard everything — never touch the submitted values
        return redirect(url_for('user.phishing_caught', source='bank'))
    return render_template('phishing/bank.html')


@user_bp.route('/phishing/social', methods=['GET', 'POST'])
@login_required
def phishing_social():
    if request.method == 'POST':
        return redirect(url_for('user.phishing_caught', source='social'))
    return render_template('phishing/social.html')


@user_bp.route('/phishing/caught')
@login_required
def phishing_caught():
    source = request.args.get('source', 'bank')
    return render_template('phishing/caught.html', source=source)
