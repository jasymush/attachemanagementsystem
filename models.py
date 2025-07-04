from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """
    User model for authentication and role-based access.
    """
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    institution = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False) # Increased length for password hash
    role = db.Column(db.String(50), nullable=False) # 'Attachee', 'Supervisor', 'Director'
    department = db.Column(db.String(50), nullable=False) # 'ICT', 'Finance', 'Planning', 'Human Resource'
    ministry_rating = db.Column(db.Integer, default=0) # 1-5 stars
    is_active = db.Column(db.Boolean, default=False) # Field for admin verification
    reset_token = db.Column(db.String(100), nullable=True) # Field to store password reset token
    reset_token_timestamp = db.Column(db.DateTime, nullable=True) # NEW: Timestamp for token generation

    # Relationship with Report model
    reports = db.relationship('Report', backref='author', lazy=True)

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the stored hash."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"User('{self.full_name}', '{self.email}', '{self.role}', '{self.department}')"

class Report(db.Model):
    """
    Report model for attachee submissions.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_type = db.Column(db.String(50), nullable=False) # 'absent_days', 'complaint', 'recommendation'
    subject = db.Column(db.String(200), nullable=True)
    details = db.Column(db.Text, nullable=False)
    date_submitted = db.Column(db.DateTime, nullable=False, default=datetime.datetime.utcnow)
    start_date = db.Column(db.Date, nullable=True) # For 'absent_days'
    end_date = db.Column(db.Date, nullable=True)   # For 'absent_days'
    reason = db.Column(db.Text, nullable=True)     # For 'absent_days'

    def __repr__(self):
        return f"Report('{self.report_type}', '{self.subject}', '{self.date_submitted}')"

