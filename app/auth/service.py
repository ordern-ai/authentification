# app/auth/service.py
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import decode_token
from datetime import datetime
from functools import wraps
from app.models import User, AuthLog
from app import db

service_bp = Blueprint("auth_service", __name__)


def validate_service_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("X-Service-API-Key")
        if not api_key:
            return jsonify({"error": "Service API key is required"}), 401

        if api_key != current_app.config["SERVICE_API_KEY"]:
            return jsonify({"error": "Invalid service API key"}), 401

        return f(*args, **kwargs)

    return decorated


def log_service_auth(user_id, service_name, status):
    """Log authentication attempts from external services"""
    try:
        auth_log = AuthLog(
            user_id=user_id,
            event_type=f"service_auth_{service_name}",
            ip_address=request.remote_addr,
            user_agent=request.headers.get("User-Agent", ""),
            status=status,
        )
        db.session.add(auth_log)
        db.session.commit()
    except Exception as e:
        current_app.logger.error(f"Error logging service auth: {str(e)}")
        db.session.rollback()


@service_bp.route("/verify-token", methods=["POST"])
@validate_service_key
def verify_token():
    """Verify JWT token and return user information"""
    try:
        data = request.get_json()
        token = data.get("token")

        if not token:
            return jsonify({"error": "Token is required"}), 400

        # Decode and verify the token
        try:
            decoded_token = decode_token(token)
            user_id = decoded_token["sub"]

            # Check if token is expired
            exp_timestamp = decoded_token["exp"]
            if datetime.fromtimestamp(exp_timestamp) < datetime.utcnow():
                log_service_auth(user_id, "token_verification", "failure")
                return jsonify({"error": "Token has expired"}), 401

            # Get user information
            user = User.query.get(user_id)
            if not user or not user.is_active:
                log_service_auth(user_id, "token_verification", "failure")
                return jsonify({"error": "User not found or inactive"}), 401

            log_service_auth(user.id, "token_verification", "success")

            return (
                jsonify(
                    {
                        "valid": True,
                        "user": {
                            "id": user.id,
                            "email": user.email,
                            "role": user.role,
                            "company_id": user.company_id,
                            "is_active": user.is_active,
                        },
                    }
                ),
                200,
            )

        except Exception as e:
            return jsonify({"error": "Invalid token", "details": str(e)}), 401

    except Exception as e:
        current_app.logger.error(f"Token verification error: {str(e)}")
        return jsonify({"error": "Error processing request"}), 500


@service_bp.route("/user-info/<int:user_id>", methods=["GET"])
@validate_service_key
def get_user_info(user_id):
    """Get detailed user information for a specific user"""
    try:
        user = User.query.get(user_id)
        if not user:
            log_service_auth(user_id, "user_info_request", "failure")
            return jsonify({"error": "User not found"}), 404

        log_service_auth(user.id, "user_info_request", "success")

        return jsonify({"user": user.to_dict()}), 200

    except Exception as e:
        current_app.logger.error(f"Error retrieving user info: {str(e)}")
        return jsonify({"error": "Error processing request"}), 500


@service_bp.route("/check-permission", methods=["POST"])
@validate_service_key
def check_permission():
    """Check if a user has specific permissions"""
    try:
        data = request.get_json()
        user_id = data.get("user_id")
        required_role = data.get("required_role")

        if not all([user_id, required_role]):
            return jsonify({"error": "User ID and required role are required"}), 400

        user = User.query.get(user_id)
        if not user or not user.is_active:
            log_service_auth(user_id, "permission_check", "failure")
            return jsonify({"error": "User not found or inactive"}), 404

        # Simple role check - can be expanded based on your permission system
        has_permission = user.role == required_role or user.role == "admin"

        log_service_auth(user.id, "permission_check", "success")

        return jsonify({"has_permission": has_permission, "user_role": user.role}), 200

    except Exception as e:
        current_app.logger.error(f"Permission check error: {str(e)}")
        return jsonify({"error": "Error processing request"}), 500
