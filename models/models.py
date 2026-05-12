from models.database import db
from datetime import datetime

# User table — stores registered users and admins
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), default='user')  # 'user' or 'admin'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# UrlScan table — stores every URL scan result
class UrlScan(db.Model):
    __tablename__ = 'url_scans'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    scanned_url = db.Column(db.String(500), nullable=False)
    score = db.Column(db.Integer, default=0)
    result = db.Column(db.String(20))  # 'Low Risk', 'Medium Risk', 'High Risk'
    reasons = db.Column(db.Text)       # explanation text
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# PhishingTemplate table — fake email templates created by admin
class PhishingTemplate(db.Model):
    __tablename__ = 'phishing_templates'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    sender_name = db.Column(db.String(100), nullable=False)
    body = db.Column(db.Text, nullable=False)
    fake_url = db.Column(db.String(500))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Feedback table — stores user ratings and comments
class Feedback(db.Model):
    __tablename__ = 'feedback'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    message = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer)  # 1 to 5
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
