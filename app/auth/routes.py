# app/auth/routes.py
import random
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
)
from datetime import datetime, timedelta
import re

from app.auth.token import refresh_access_token
from app.auth.two_factor import send_email_code, send_sms_code, generate_totp_secret
from app.logging import log_auth_event
from ..models import User, AuthLog, Company
from .. import db, bcrypt

auth_bp = Blueprint("auth", __name__)


def check_account_lockout(user):
    """Check if account is locked due to failed attempts"""
    if not user:
        return False

    # Check for failed attempts in the last 30 minutes
    thirty_mins_ago = datetime.now() - timedelta(minutes=30)
    failed_attempts = AuthLog.query.filter(
        AuthLog.user_id == user.id,
        AuthLog.event_type == "failed_login",
        AuthLog.created_at >= thirty_mins_ago,
    ).count()

    return failed_attempts >= current_app.config.get("MAX_LOGIN_ATTEMPTS", 5)


from flask import Blueprint, request, jsonify
from ..models import User, Company, AuthLog
from .. import db, bcrypt
from .validators import validate_password, validate_email


@auth_bp.route("/register", methods=["POST"])
def register():
    try:
        data = request.get_json()

        # Validate required fields
        if not all(field in data for field in ["email", "password"]):
            return jsonify({"error": "Email and password are required"}), 400

        # Validate email format
        if not validate_email(data["email"]):
            return jsonify({"error": "Invalid email format"}), 400

        # Validate password strength
        if not validate_password(data["password"]):
            return (
                jsonify(
                    {
                        "error": "Password must be at least 8 characters and contain uppercase, lowercase, and numbers"
                    }
                ),
                400,
            )

        # Check if email is already registered
        if User.query.filter_by(email=data["email"]).first():
            return jsonify({"error": "Email already registered"}), 400

        # Check company if provided
        company_id = data.get("company_id")
        if company_id is not None:
            company = Company.query.get(company_id)
            if not company:
                return jsonify({"error": "Invalid company ID"}), 400

        # Create new user
        user = User(
            email=data["email"],
            password_hash=bcrypt.generate_password_hash(data["password"]).decode(
                "utf-8"
            ),
            company_id=company_id,  # This will be None if not provided
            role=data.get("role", "user"),  # Default to 'user' if not specified
        )

        db.session.add(user)
        db.session.commit()

        # Log successful registration
        log_auth_event(user.id, "registration", request, "success")

        # Return success response
        return (
            jsonify(
                {
                    "message": "User registered successfully",
                    "user_id": user.id,
                    "email": user.email,
                    "role": user.role,
                    "company_id": user.company_id,
                }
            ),
            201,
        )

    except Exception as e:
        db.session.rollback()
        log_auth_event(None, "registration_failed", request, "failure")
        current_app.logger.error(f"Registration failed: {str(e)}")
        return jsonify({"error": "Registration failed. Please try again later"}), 500


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()

    # Validate required fields
    if not all(k in data for k in ["email", "password"]):
        return jsonify({"error": "Missing email or password"}), 400

    user = User.query.filter_by(email=data["email"]).first()

    # Check if account is locked
    if check_account_lockout(user):
        log_auth_event(user.id, "account_locked", request, "failure")
        return (
            jsonify(
                {"error": "Account temporarily locked due to too many failed attempts"}
            ),
            403,
        )

    if not user or not bcrypt.check_password_hash(user.password_hash, data["password"]):
        log_auth_event(user.id if user else None, "failed_login", request, "failure")
        return jsonify({"error": "Invalid credentials"}), 401

    # Check if user is active
    if not user.is_active:
        log_auth_event(user.id, "inactive_account_login_attempt", request, "failure")
        return jsonify({"error": "Account is inactive"}), 403

    if user.two_factor_enabled:
        try:
            # Generate and send 2FA code based on user's preferred method
            if user.two_factor_method == "email":
                code = str(random.randint(100000, 999999))
                send_email_code(user.email, code)
                user.two_factor_secret = code
            elif user.two_factor_method == "sms":
                code = str(random.randint(100000, 999999))
                send_sms_code(user.phone_number, code)
                user.two_factor_secret = code
            # For authenticator app, secret is already set

            db.session.commit()
            return (
                jsonify(
                    {
                        "message": "2FA required",
                        "user_id": user.id,
                        "method": user.two_factor_method,
                    }
                ),
                200,
            )

        except Exception as e:
            log_auth_event(user.id, "2fa_setup_failed", request, "failure")
            return jsonify({"error": "Error setting up 2FA"}), 500


    try:
        # Create both tokens separately
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)

        log_auth_event(user.id, "login", request, "success")

        return (
            jsonify(
                {
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "user": {
                        "id": user.id,
                        "email": user.email,
                        "role": user.role,
                        "company_id": user.company_id,
                        "two_factor_enabled": user.two_factor_enabled,
                    },
                }
            ),
            200,
        )

    except Exception as e:
        print(e)
        log_auth_event(user.id, "token_creation_failed", request, "failure")
        return jsonify({"error": "Error creating access token"}), 500


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """Refresh an access token using a refresh token"""
    current_user_id = get_jwt_identity()

    # Verify user still exists and is active
    user = User.query.get(current_user_id)
    if not user or not user.is_active:
        log_auth_event(current_user_id, "token_refresh_failed", request, "failure")
        return jsonify({"error": "Invalid or inactive user"}), 401

    try:
        new_access_token = refresh_access_token(current_user_id)
        log_auth_event(current_user_id, "token_refresh", request, "success")
        return jsonify({"access_token": new_access_token}), 200

    except Exception as e:
        log_auth_event(current_user_id, "token_refresh_failed", request, "failure")
        return jsonify({"error": "Error refreshing access token"}), 500


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """Log out a user and invalidate their tokens"""
    current_user_id = get_jwt_identity()

    try:
        # Log the logout event
        log_auth_event(current_user_id, "logout", request, "success")

        # In a production environment, you might want to add the token to a blacklist
        # or invalidate it in your token storage

        return jsonify({"message": "Successfully logged out"}), 200

    except Exception as e:
        log_auth_event(current_user_id, "logout_failed", request, "failure")
        return jsonify({"error": "Error during logout"}), 500
