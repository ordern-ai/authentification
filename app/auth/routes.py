# app/auth/routes.py
import random
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_jwt,
    get_jwt_identity,
    jwt_required,
)
from datetime import datetime, timedelta

import redis


from app.auth.token import refresh_access_token
from app.two_factor.routes import send_email_code, send_sms_code, generate_totp_secret
from app.logging import log_auth_event
from ..models import User, AuthLog, Company
from .. import db, bcrypt


from flask import Blueprint, request, jsonify, current_app, url_for
from werkzeug.utils import secure_filename
import os
import uuid
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

from app.auth.validators import validate_phone_number
from app.utils.email import send_password_reset_email, send_email_suspicous_activity
from app.utils.sms import send_suspicious_activity
from app.blacklisting import add_token_to_blacklist, redis_client

auth_bp = Blueprint("auth", __name__)

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


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


# ---------------------------------------------------------------------------- #
#                                   Register                                   #
# ---------------------------------------------------------------------------- #


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


# ---------------------------------------------------------------------------- #
#                                     LOGIN                                    #
# ---------------------------------------------------------------------------- #


def handle_2fa_setup(user, request):
    """Handle 2FA setup and code generation"""
    try:
        if user.two_factor_method == "email":
            code = str(random.randint(100000, 999999))
            send_email_code(user.email, code)
            user.two_factor_secret = code
            db.session.commit()

        elif user.two_factor_method == "sms":
            if not user.phone_number:
                return (
                    jsonify(
                        {
                            "error": "Phone number not set. Please set it to continue with SMS 2FA."
                        }
                    ),
                    400,
                )

            code = str(random.randint(100000, 999999))
            send_sms_code(user.phone_number, code)
            user.two_factor_secret = code
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
        db.session.rollback()
        log_auth_event(user.id, "2fa_setup_failed", request, "failure")
        logger.error(f"2FA setup failed: {str(e)}")
        return (
            jsonify(
                {"error": "Error setting up 2FA. Please try again or contact support."}
            ),
            500,
        )


def complete_login(user, request):
    """Complete the login process by generating tokens"""
    try:
        additional_claims = {"role": user.role, "email": user.email}

        access_token = create_access_token(
            identity=str(user.id), additional_claims=additional_claims
        )
        refresh_token = create_refresh_token(
            identity=str(user.id), additional_claims=additional_claims
        )

        log_auth_event(user.id, "login", request, "success")

        response = jsonify(
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
        )

        # Add security headers
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            }
        )

        return response, 200

    except Exception as e:
        logger.error(f"Token creation error: {str(e)}")
        log_auth_event(user.id, "token_creation_failed", request, "failure")
        return jsonify({"error": "Error creating access token"}), 500


def debug_redis_key(key):
    """Debug helper to check Redis key state"""
    try:
        exists = redis_client.exists(key)
        value = redis_client.get(key) if exists else None
        type_result = redis_client.type(key) if exists else None
        logger.info(
            f"Redis key '{key}' exists: {exists}, type: {type_result}, value: {value}"
        )
        return exists, value, type_result
    except redis.RedisError as e:
        logger.error(f"Redis debug error: {str(e)}")
        return False, None, None


@auth_bp.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        ip = request.remote_addr
        attempts_key = f"login_attempts:{ip}"

        # Get current attempts count with defensive handling
        try:
            attempts = int(redis_client.get(attempts_key) or 0)
            max_attempts = current_app.config.get("MAX_LOGIN_ATTEMPTS", 5)

            # Check if already exceeded
            if attempts >= max_attempts:

                # Log suspicious activity
                user = User.query.filter_by(email=data["email"]).first()

                if user:
                    if user.phone_number:
                        send_suspicious_activity(user.phone_number)
                    if user.email:
                        send_email_suspicous_activity(user.email)

                log_auth_event(user.id, "suspicious_activity", request, "failure")

                return (
                    jsonify(
                        {"error": "Too many login attempts. Please try again later"}
                    ),
                    429,
                )

        except redis.RedisError as e:
            logger.error(f"Redis error checking login attempts: {str(e)}")
            attempts = 0

        # Validate required fields
        if not all(k in data for k in ["email", "password"]):
            return jsonify({"error": "Missing email or password"}), 400

        user = User.query.filter_by(email=data["email"]).first()

        if not user or not bcrypt.check_password_hash(
            user.password_hash, data["password"]
        ):
            # Increment attempt counter safely
            try:
                # Use pipeline to make operations atomic
                with redis_client.pipeline() as pipe:
                    pipe.incr(attempts_key)
                    pipe.expire(attempts_key, 1800)  # 30 minutes expiry
                    pipe.execute()
            except redis.RedisError as e:
                logger.error(f"Redis error incrementing attempts: {str(e)}")

            log_auth_event(
                user.id if user else None, "failed_login", request, "failure"
            )
            return jsonify({"error": "Invalid credentials"}), 401

        # If login successful, reset attempts counter
        try:
            redis_client.delete(attempts_key)
        except redis.RedisError as e:
            logger.error(f"Redis error resetting attempts: {str(e)}")

        # Check if account is locked
        if check_account_lockout(user):
            log_auth_event(user.id, "account_locked", request, "failure")
            return (
                jsonify(
                    {
                        "error": "Account temporarily locked due to too many failed attempts"
                    }
                ),
                403,
            )

        # Check if user is active
        if not user.is_active:
            log_auth_event(
                user.id, "inactive_account_login_attempt", request, "failure"
            )
            return jsonify({"error": "Account is inactive"}), 403

        # Handle 2FA
        if user.two_factor_enabled:
            return handle_2fa_setup(user, request)

        try:
            redis_client.delete(attempts_key)
        except redis.RedisError as e:
            logger.error(f"Redis error cleaning up attempts: {str(e)}")

        # Generate tokens and complete login
        return complete_login(user, request)

    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({"error": "An unexpected error occurred"}), 500


# ---------------------------------------------------------------------------- #
#                                 refresh token                                #
# ---------------------------------------------------------------------------- #


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


# ---------------------------------------------------------------------------- #
#                                    Logout                                    #
# ---------------------------------------------------------------------------- #


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """Log out a user and invalidate their tokens"""
    current_user_id = get_jwt_identity()

    try:
        # Get claims from the current access token
        jwt_claims = get_jwt()
        jti = jwt_claims.get("jti")
        exp = jwt_claims.get("exp")

        if jti and exp:
            blacklist_success = add_token_to_blacklist(jti, exp)
            if not blacklist_success:
                logger.warning(
                    f"Failed to blacklist access token for user {current_user_id}"
                )

        # Handle refresh token if provided
        refresh_token = request.json.get("refresh_token")
        if refresh_token:
            try:
                refresh_claims = decode_token(refresh_token)
                refresh_jti = refresh_claims.get("jti")
                refresh_exp = refresh_claims.get("exp")

                if refresh_jti and refresh_exp:
                    blacklist_success = add_token_to_blacklist(refresh_jti, refresh_exp)
                    if not blacklist_success:
                        logger.warning(
                            f"Failed to blacklist refresh token for user {current_user_id}"
                        )
            except Exception as e:
                logger.warning(
                    f"Invalid refresh token provided during logout: {str(e)}"
                )

        # Log the successful logout event
        log_auth_event(current_user_id, "logout", request, "success")

        return jsonify({"message": "Successfully logged out", "status": "success"}), 200

    except Exception as e:
        logger.error(f"Logout error for user {current_user_id}: {str(e)}")
        log_auth_event(current_user_id, "logout_failed", request, "failure")
        return jsonify({"error": "Error during logout", "status": "error"}), 500


def cleanup_expired_blacklist():
    """Cleanup function to remove expired tokens from blacklist"""
    try:
        pattern = "blacklist_token_*"
        for key in redis_client.scan_iter(match=pattern):
            # Redis will automatically remove expired keys
            # This function is mainly for documentation
            pass
    except redis.RedisError as e:
        logger.error(f"Error during blacklist cleanup: {str(e)}")


# ---------------------------------------------------------------------------- #
#                               update user info                               #
# ---------------------------------------------------------------------------- #


@auth_bp.route("/user/update", methods=["PUT"])
@jwt_required()
def update_user():
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404

        data = request.form if request.files else request.get_json()

        # Update basic information
        if "full_name" in data:
            user.full_name = data["full_name"]

        if "email" in data:
            if User.query.filter(
                User.email == data["email"], User.id != current_user_id
            ).first():
                return jsonify({"error": "Email already in use"}), 400
            user.email = data["email"]

        if "phone_number" in data:
            phone_number = data["phone_number"]
            if not validate_phone_number(phone_number):
                return jsonify({"error": "Invalid phone number format"}), 400
            if User.query.filter(
                User.phone_number == phone_number, User.id != current_user_id
            ).first():
                return jsonify({"error": "Phone number already in use"}), 400
            user.phone_number = phone_number

        # Handle profile image upload
        if request.files and "profile_image" in request.files:
            file = request.files["profile_image"]
            if file and allowed_file(file.filename):
                filename = secure_filename(f"{uuid.uuid4()}_{file.filename}")
                upload_path = os.path.join(
                    current_app.config["UPLOAD_FOLDER"], filename
                )
                file.save(upload_path)
                user.profile_image_url = url_for(
                    "static", filename=f"uploads/{filename}", _external=True
                )

        db.session.commit()
        log_auth_event(user.id, "profile_update", request, "success")

        return (
            jsonify(
                {"message": "Profile updated successfully", "user": user.to_dict()}
            ),
            200,
        )

    except Exception as e:
        db.session.rollback()
        log_auth_event(current_user_id, "profile_update_failed", request, "failure")
        current_app.logger.error(f"Profile update failed: {str(e)}")
        return jsonify({"error": "Failed to update profile"}), 500


# ---------------------------------------------------------------------------- #
#                            Request password reset                            #
# ---------------------------------------------------------------------------- #


@auth_bp.route("/password/request-reset", methods=["POST"])
def request_password_reset():
    try:
        data = request.get_json()
        email = data.get("email")

        if not email:
            return jsonify({"error": "Email is required"}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            # Return success even if user not found to prevent email enumeration
            return (
                jsonify(
                    {
                        "message": "If your email is registered, you will receive reset instructions"
                    }
                ),
                200,
            )

        # Generate reset token
        reset_token = str(uuid.uuid4())
        user.password_reset_token = reset_token
        user.password_reset_expires = datetime.now() + timedelta(hours=24)

        db.session.commit()

        # Send reset email
        send_password_reset_email(user.email, reset_token)
        log_auth_event(user.id, "password_reset_requested", request, "success")

        return jsonify({"message": "Password reset instructions sent"}), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Password reset request failed: {str(e)}")
        return jsonify({"error": "Failed to process password reset request"}), 500


# ---------------------------------------------------------------------------- #
#                                reset password                                #
# ---------------------------------------------------------------------------- #


@auth_bp.route("/password/reset", methods=["POST"])
def reset_password():
    try:
        data = request.get_json()
        token = data.get("token")
        new_password = data.get("password")

        if not all([token, new_password]):
            return jsonify({"error": "Token and new password are required"}), 400

        user = User.query.filter_by(password_reset_token=token).first()
        if (
            not user
            or not user.password_reset_expires
            or user.password_reset_expires < datetime.now()
        ):
            return jsonify({"error": "Invalid or expired reset token"}), 400

        if not validate_password(new_password):
            return jsonify({"error": "Password does not meet requirements"}), 400

        # Update password
        user.password_hash = bcrypt.generate_password_hash(new_password).decode("utf-8")
        user.password_reset_token = None
        user.password_reset_expires = None

        db.session.commit()
        log_auth_event(user.id, "password_reset_completed", request, "success")

        return jsonify({"message": "Password reset successfully"}), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Password reset failed: {str(e)}")
        return jsonify({"error": "Failed to reset password"}), 500


# ---------------------------------------------------------------------------- #
#                              Session management                              #
# ---------------------------------------------------------------------------- #


@auth_bp.route("/sessions", methods=["GET"])
@jwt_required()
def get_active_sessions():
    """Get all active sessions for the current user"""
    try:
        user_id = get_jwt_identity()
        sessions = AuthLog.query.filter(
            AuthLog.user_id == user_id,
            AuthLog.event_type == "login",
            AuthLog.created_at >= (datetime.now() - timedelta(days=30)),
        ).all()

        return (
            jsonify(
                {
                    "sessions": [
                        {
                            "id": session.id,
                            "ip_address": session.ip_address,
                            "user_agent": session.user_agent,
                            "created_at": session.created_at.isoformat(),
                        }
                        for session in sessions
                    ]
                }
            ),
            200,
        )

    except Exception as e:
        return jsonify({"error": "Failed to retrieve sessions"}), 500


@auth_bp.route("/sessions/<int:session_id>", methods=["DELETE"])
@jwt_required()
def terminate_session(session_id):
    """Terminate a specific session"""
    try:
        user_id = get_jwt_identity()
        session = AuthLog.query.filter_by(id=session_id, user_id=user_id).first()

        if not session:
            return jsonify({"error": "Session not found"}), 404

        # Add associated token to blacklist
        jwt_claims = get_jwt()
        add_token_to_blacklist(jwt_claims["jti"], jwt_claims["exp"])

        log_auth_event(user_id, "session_terminated", request, "success")
        return jsonify({"message": "Session terminated successfully"}), 200

    except Exception as e:
        return jsonify({"error": "Failed to terminate session"}), 500
