# models.py is used to define the structure of the database tables.

from . import db
from datetime import datetime


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    company_id = db.Column(
        db.Integer, db.ForeignKey("company.id"), nullable=True
    )  # Made nullable
    role = db.Column(db.String(20), default="user")
    is_active = db.Column(db.Boolean, default=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_method = db.Column(db.String(20))
    two_factor_secret = db.Column(db.String(32))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)

    def __repr__(self):
        return f"<User {self.email}>"

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "company_id": self.company_id,
            "role": self.role,
            "is_active": self.is_active,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login": self.last_login.isoformat() if self.last_login else None,
        }


class Company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    users = db.relationship("User", backref="company", lazy=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class AuthLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    event_type = db.Column(db.String(50))  # login, logout, failed_login, 2fa_attempt
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.String(200))
    status = db.Column(db.String(20))  # success, failure
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
