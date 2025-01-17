from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    get_jwt_identity,
    jwt_required,
)

from app.auth.token import refresh_access_token
from app.logging import log_auth_event
from ..models import User, AuthLog
from .. import db, bcrypt

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.get_json()

    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already registered"}), 400

    user = User(
        email=data["email"],
        password_hash=bcrypt.generate_password_hash(data["password"]).decode("utf-8"),
        company_id=data.get("company_id"),
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({"message": "User registered successfully"}), 201


@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()

    if not user or not bcrypt.check_password_hash(user.password_hash, data["password"]):
        log_auth_event(None, "failed_login", request, "failure")
        return jsonify({"error": "Invalid credentials"}), 401

    if user.two_factor_enabled:
        # Handle 2FA
        return jsonify({"message": "2FA required", "user_id": user.id}), 200

    try:
        access_token, refresh_token = create_access_token(user.id)

        # Log successful login
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
                    },
                }
            ),
            200,
        )

    except Exception as e:
        log_auth_event(user.id, "token_creation_failed", request, "failure")
        return jsonify({"error": "Error creating access token"}), 500


@auth_bp.route("/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh():
    """
    Endpoint to refresh an access token using a refresh token
    """
    current_user_id = get_jwt_identity()

    try:
        new_access_token = refresh_access_token(current_user_id)

        return jsonify({"access_token": new_access_token}), 200

    except Exception as e:
        log_auth_event(current_user_id, "token_refresh_failed", request, "failure")
        return jsonify({"error": "Error refreshing access token"}), 500


@auth_bp.route("/logout", methods=["POST"])
@jwt_required()
def logout():
    """
    Endpoint to logout a user
    Note: Client should discard tokens
    """
    current_user_id = get_jwt_identity()

    # Log the logout event
    log_auth_event(current_user_id, "logout", request, "success")

    return jsonify({"message": "Successfully logged out"}), 200
