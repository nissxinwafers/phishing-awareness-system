import os
from flask import Flask
from models.database import db
from models.models import User, UrlScan, PhishingTemplate, Feedback
from routes.auth import auth_bp
from routes.user import user_bp
from routes.admin import admin_bp

# Initialize the Flask app
app = Flask(__name__)

# Secret key for sessions
app.config['SECRET_KEY'] = 'phishing-awareness-secret-key'

# Build the absolute path to the database file
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATABASE_DIR = os.path.join(BASE_DIR, 'database')

# Make sure the database folder exists
os.makedirs(DATABASE_DIR, exist_ok=True)

# Use absolute path for SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(DATABASE_DIR, 'phishing.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Connect the database to the app
db.init_app(app)

# Register route blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(user_bp)
app.register_blueprint(admin_bp)

# Create all tables on first run
with app.app_context():
    db.create_all()
    print("[OK] Database tables created successfully.")

if __name__ == '__main__':
    app.run(debug=True)
