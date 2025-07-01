from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    """
    User model representing users of the Attaches Management System.
    Includes authentication details, personal information, and role-based access.
    """
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    institution = db.Column(db.String(100), nullable=False)
    # Increased length of password_hash to accommodate longer hashes (e.g., scrypt)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(50), nullable=False) # Attachee, Supervisor, Director
    department = db.Column(db.String(50), nullable=False) # ICT, Finance, Planning, Human Resource
    ministry_rating = db.Column(db.Integer, default=0) # 1-5 stars

    # Relationship with Report model (one-to-many: one user can have many reports)
    reports = db.relationship('Report', backref='author', lazy=True)

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Checks if the provided password matches the hashed password."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.email}>"

class Report(db.Model):
    """
    Report model for attachee submissions (days absent, complaints, recommendations).
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    report_type = db.Column(db.String(50), nullable=False) # 'absent_days', 'complaint', 'recommendation'
    subject = db.Column(db.String(200), nullable=True) # Subject for complaints/recommendations
    details = db.Column(db.Text, nullable=False)
    date_submitted = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    # Specific fields for 'absent_days' type
    start_date = db.Column(db.Date, nullable=True)
    end_date = db.Column(db.Date, nullable=True)
    reason = db.Column(db.Text, nullable=True) # Reason for absence

    def __repr__(self):
        return f"<Report {self.report_type} by User {self.user_id}>"

# Note: Department model is not explicitly needed as department is a field in User.
# If departments needed their own properties or relationships, a separate model would be useful.
