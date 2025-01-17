# app/auth/two_factor.py
import base64
from secrets import token_bytes
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_required,
    get_jwt_identity,
)

from pyotp import TOTP

from app.logging import log_auth_event
from app.utils.totp import generate_totp_secret, verify_totp
from ..models import User, AuthLog
from .. import db
import os

from app.utils.email import send_email_code
from app.utils.sms import send_sms_code


two_factor_bp = Blueprint("two_factor", __name__)


# ---------------------------------------------------------------------------- #
#                                   Setup 2FA                                  #
# ---------------------------------------------------------------------------- #


@two_factor_bp.route("/setup", methods=["POST"])
@jwt_required()
def setup_2fa():
    """Setup 2FA for a user"""

    try:
        # Get current user ID from JWT
        current_user_id = get_jwt_identity()

        if not current_user_id:
            return jsonify({"error": "Invalid token", "code": "invalid_token"}), 401

        # Get user from database
        current_user = User.query.get(current_user_id)
        if not current_user:
            return jsonify({"error": "User not found", "code": "user_not_found"}), 404

        # Get and validate 2FA method
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided", "code": "no_data"}), 400

        method = data.get("method")
        if not method:
            return (
                jsonify({"error": "Method is required", "code": "method_required"}),
                400,
            )

        if method not in ["email", "sms", "authenticator"]:
            return (
                jsonify({"error": "Invalid 2FA method", "code": "invalid_method"}),
                400,
            )

        # Setup 2FA based on method
        if method == "authenticator":
            secret = generate_totp_secret()
            current_user.two_factor_secret = secret
            provisioning_uri = TOTP(secret).provisioning_uri(
                current_user.email, issuer_name="Ordern AI"
            )
        else:
            current_user.two_factor_secret = None
            provisioning_uri = None

        current_user.two_factor_method = method
        current_user.two_factor_enabled = True

        db.session.commit()

        # Prepare response
        response_data = {"message": "2FA setup successful"}
        if provisioning_uri:
            response_data["provisioning_uri"] = provisioning_uri
            response_data["secret"] = secret

        return jsonify(response_data), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"2FA setup failed: {str(e)}")
        return jsonify({"error": "Failed to setup 2FA", "code": "setup_failed"}), 500


# ---------------------------------------------------------------------------- #
#                                verify 2FA code                               #
# ---------------------------------------------------------------------------- #


@two_factor_bp.route("/verify", methods=["POST"])
def verify_2fa():
    """Verify 2FA code during login"""
    data = request.get_json()
    user_id = data.get("user_id")
    code = data.get("code")

    user = User.query.get(user_id)
    if not user or not user.two_factor_enabled:
        return jsonify({"error": "Invalid request"}), 400

    verified = False
    if user.two_factor_method == "authenticator":
        verified = verify_totp(user.two_factor_secret, code)
    else:
        # For email and SMS, verify against stored temporary code
        verified = code == user.two_factor_secret

    if verified:
        # Clear temporary code if using email/SMS
        if user.two_factor_method in ["email", "sms"]:
            user.two_factor_secret = None
            db.session.commit()

        # Create new auth log entry
        log = AuthLog(
            user_id=user.id,
            event_type="2fa_verification",
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            status="success",
        )
        db.session.add(log)
        db.session.commit()

        additional_claims = {"role": user.role, "email": user.email}

        # Generate new JWT tokens
        access_token = create_access_token(
            identity=str(user.id), additional_claims=additional_claims
        )
        refresh_token = create_refresh_token(identity=str(user.id))

        refresh_token = create_refresh_token(
            identity=str(user.id), additional_claims=additional_claims
        )

        log_auth_event(user.id, "login", request, "success")

        return jsonify({"access_token": access_token, "refresh_token": refresh_token})

    # Log failed attempt
    log = AuthLog(
        user_id=user.id,
        event_type="2fa_verification",
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        status="failure",
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({"error": "Invalid verification code"}), 401


# ---------------------------------------------------------------------------- #
#                                  Disable 2FA                                 #
# ---------------------------------------------------------------------------- #


@two_factor_bp.route("/disable", methods=["POST"])
@jwt_required()
def disable_2fa():
    """Disable 2FA for a user"""
    current_user = User.query.get(get_jwt_identity())

    current_user.two_factor_enabled = False
    current_user.two_factor_method = None
    current_user.two_factor_secret = None

    db.session.commit()

    return jsonify({"message": "2FA disabled successfully"})
