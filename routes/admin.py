from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from models.database import db
from models.models import User, UrlScan, PhishingTemplate, Feedback, SentEmail

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


# ── Admin guard ───────────────────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('auth.login'))
        if session.get('user_role') != 'admin':
            flash('You do not have permission to access that page.', 'danger')
            return redirect(url_for('user.dashboard'))
        return f(*args, **kwargs)
    return decorated


# ── Dashboard ─────────────────────────────────────────────────────────────────
@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    total_users     = User.query.count()
    total_scans     = UrlScan.query.count()
    total_feedback  = Feedback.query.count()
    high_risk       = UrlScan.query.filter_by(result='High Risk').count()
    medium_risk     = UrlScan.query.filter_by(result='Medium Risk').count()
    low_risk        = UrlScan.query.filter_by(result='Low Risk').count()
    total_templates = PhishingTemplate.query.count()

    recent_scans = (
        UrlScan.query
        .order_by(UrlScan.created_at.desc())
        .limit(8).all()
    )
    recent_feedback = (
        Feedback.query
        .order_by(Feedback.created_at.desc())
        .limit(5).all()
    )
    # Preload usernames for scan rows
    user_map = {u.id: u.name for u in User.query.all()}

    return render_template(
        'admin/dashboard.html',
        total_users=total_users,
        total_scans=total_scans,
        total_feedback=total_feedback,
        high_risk=high_risk,
        medium_risk=medium_risk,
        low_risk=low_risk,
        total_templates=total_templates,
        recent_scans=recent_scans,
        recent_feedback=recent_feedback,
        user_map=user_map,
    )


# ── Phishing templates — list ─────────────────────────────────────────────────
@admin_bp.route('/templates')
@admin_required
def templates():
    page = request.args.get('page', 1, type=int)
    templates_page = (
        PhishingTemplate.query
        .order_by(PhishingTemplate.created_at.desc())
        .paginate(page=page, per_page=10, error_out=False)
    )
    return render_template('admin/templates.html', templates_page=templates_page)


# ── Phishing templates — create ───────────────────────────────────────────────
@admin_bp.route('/templates/create', methods=['GET', 'POST'])
@admin_required
def template_create():
    if request.method == 'POST':
        title       = request.form.get('title', '').strip()
        subject     = request.form.get('subject', '').strip()
        sender_name = request.form.get('sender_name', '').strip()
        body        = request.form.get('body', '').strip()
        fake_url    = request.form.get('fake_url', '').strip()

        if not all([title, subject, sender_name, body]):
            flash('Title, subject, sender name and body are all required.', 'danger')
            return render_template('admin/template_create.html')

        t = PhishingTemplate(
            title=title,
            subject=subject,
            sender_name=sender_name,
            body=body,
            fake_url=fake_url or None,
        )
        db.session.add(t)
        db.session.commit()

        flash(f'Template "{title}" created successfully.', 'success')
        return redirect(url_for('admin.template_view', template_id=t.id))

    return render_template('admin/template_create.html')


# ── Phishing templates — view / email preview ─────────────────────────────────
@admin_bp.route('/templates/<int:template_id>')
@admin_required
def template_view(template_id):
    t = PhishingTemplate.query.get_or_404(template_id)
    return render_template('admin/template_view.html', t=t)


# ── Phishing templates — delete ───────────────────────────────────────────────
@admin_bp.route('/templates/<int:template_id>/delete', methods=['POST'])
@admin_required
def template_delete(template_id):
    t = PhishingTemplate.query.get_or_404(template_id)
    db.session.delete(t)
    db.session.commit()
    flash(f'Template "{t.title}" deleted.', 'info')
    return redirect(url_for('admin.templates'))


# ── All users ─────────────────────────────────────────────────────────────────
@admin_bp.route('/users')
@admin_required
def users():
    page  = request.args.get('page', 1, type=int)
    query = request.args.get('q', '').strip()

    base = User.query
    if query:
        base = base.filter(
            User.name.ilike(f'%{query}%') | User.email.ilike(f'%{query}%')
        )

    users_page = base.order_by(User.created_at.desc()).paginate(
        page=page, per_page=15, error_out=False
    )

    scan_counts = {
        u.id: UrlScan.query.filter_by(user_id=u.id).count()
        for u in users_page.items
    }

    return render_template(
        'admin/users.html',
        users_page=users_page,
        scan_counts=scan_counts,
        query=query,
    )


# ── All scans ─────────────────────────────────────────────────────────────────
@admin_bp.route('/scans')
@admin_required
def scans():
    page       = request.args.get('page', 1, type=int)
    risk_filter = request.args.get('risk', '')

    base = UrlScan.query
    if risk_filter in ('High Risk', 'Medium Risk', 'Low Risk'):
        base = base.filter_by(result=risk_filter)

    scans_page = base.order_by(UrlScan.created_at.desc()).paginate(
        page=page, per_page=15, error_out=False
    )
    user_map = {u.id: u.name for u in User.query.all()}

    return render_template(
        'admin/scans.html',
        scans_page=scans_page,
        user_map=user_map,
        risk_filter=risk_filter,
    )


# ── All feedback ──────────────────────────────────────────────────────────────
@admin_bp.route('/feedback')
@admin_required
def feedback_list():
    page = request.args.get('page', 1, type=int)
    fb_page = (
        Feedback.query
        .order_by(Feedback.created_at.desc())
        .paginate(page=page, per_page=15, error_out=False)
    )
    user_map = {u.id: u.name for u in User.query.all()}

    return render_template(
        'admin/feedback.html',
        fb_page=fb_page,
        user_map=user_map,
    )

# ── Phishing templates — send to user (simulation, not real email) ────────────
@admin_bp.route('/templates/<int:template_id>/send', methods=['GET', 'POST'])
@admin_required
def template_send(template_id):
    t = PhishingTemplate.query.get_or_404(template_id)

    if request.method == 'POST':
        recipient_ids = request.form.getlist('recipient_ids')

        if not recipient_ids:
            flash('Pick at least one recipient.', 'warning')
            users = User.query.filter_by(role='user').order_by(User.name).all()
            return render_template('admin/template_send.html', t=t, users=users)

        count = 0
        for rid in recipient_ids:
            user = User.query.get(int(rid))
            if user:
                sent = SentEmail(template_id=t.id, recipient_id=user.id)
                db.session.add(sent)
                count += 1
        db.session.commit()

        flash(f'Simulated email sent to {count} user(s).', 'success')
        return redirect(url_for('admin.sent_emails'))

    users = User.query.filter_by(role='user').order_by(User.name).all()
    return render_template('admin/template_send.html', t=t, users=users)


# ── Sent emails — tracking dashboard ──────────────────────────────────────────
@admin_bp.route('/sent-emails')
@admin_required
def sent_emails():
    page = request.args.get('page', 1, type=int)
    sent_page = (
        SentEmail.query
        .order_by(SentEmail.sent_at.desc())
        .paginate(page=page, per_page=15, error_out=False)
    )
    return render_template('admin/sent_emails.html', sent_page=sent_page)


@admin_bp.route('/setup')
def setup():
    from werkzeug.security import generate_password_hash
    existing = User.query.filter_by(email='admin@phishing.com').first()
    if existing:
        return 'Admin already exists!'
    admin = User(
        name='Admin',
        email='admin@phishing.com',
        password=generate_password_hash('Admin1234'),
        role='admin'
    )
    db.session.add(admin)
    db.session.commit()
    return 'Admin created! Visit /login now.'