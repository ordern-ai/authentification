from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models import User, Company, AuthLog
from .. import db
from datetime import datetime, timedelta
from functools import wraps
from sqlalchemy import and_, or_, desc
import pytz

from werkzeug.security import generate_password_hash
from app.permissions import (
    UserRole,
    company_admin_or_higher,
    role_required,
)
from app.logging import log_admin_action

admin_bp = Blueprint("admin", __name__)


def validate_user_data(data, required_fields=None):
    """Validate user data and return error message if invalid"""
    if required_fields and not all(field in data for field in required_fields):
        return "Missing required fields"

    if "email" in data and User.query.filter_by(email=data["email"]).first():
        return "Email already registered"

    if "role" in data and data["role"] not in [role.value for role in UserRole]:
        return "Invalid role specified"

    return None


# ---------------------------------------------------------------------------- #
#                        System Configuration Management                       #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/system/configuration", methods=["GET", "PUT"])
@jwt_required()
@role_required(UserRole.SUPER_ADMIN)
def manage_system_configuration():
    current_user_id = get_jwt_identity()

    if request.method == "GET":
        config = {
            "auth_settings": {
                "jwt_expiry_hours": current_app.config.get(
                    "JWT_ACCESS_TOKEN_EXPIRES"
                ).total_seconds()
                / 3600,
                "refresh_token_expiry_days": current_app.config.get(
                    "JWT_REFRESH_TOKEN_EXPIRES"
                ).total_seconds()
                / 86400,
                "max_failed_attempts": current_app.config.get(
                    "MAX_FAILED_LOGIN_ATTEMPTS", 5
                ),
                "lockout_duration_minutes": current_app.config.get(
                    "ACCOUNT_LOCKOUT_DURATION", 30
                ),
                "password_expiry_days": current_app.config.get(
                    "PASSWORD_EXPIRY_DAYS", 90
                ),
                "require_2fa_for_admins": current_app.config.get(
                    "REQUIRE_2FA_FOR_ADMINS", True
                ),
                "session_timeout_minutes": current_app.config.get(
                    "SESSION_TIMEOUT_MINUTES", 30
                ),
                "password_history_count": current_app.config.get(
                    "PASSWORD_HISTORY_COUNT", 5
                ),
            },
            "email_settings": {
                "smtp_server": current_app.config.get("SMTP_SERVER"),
                "smtp_port": current_app.config.get("SMTP_PORT"),
                "sender_email": current_app.config.get("SENDER_EMAIL"),
                "require_email_verification": current_app.config.get(
                    "REQUIRE_EMAIL_VERIFICATION", True
                ),
            },
            "security_settings": {
                "allowed_login_ips": current_app.config.get("ALLOWED_LOGIN_IPS", []),
                "banned_ips": current_app.config.get("BANNED_IPS", []),
                "minimum_password_length": current_app.config.get(
                    "MIN_PASSWORD_LENGTH", 12
                ),
                "password_complexity": current_app.config.get(
                    "PASSWORD_COMPLEXITY",
                    {
                        "require_uppercase": True,
                        "require_lowercase": True,
                        "require_numbers": True,
                        "require_special_chars": True,
                    },
                ),
                "allowed_cors_origins": current_app.config.get(
                    "ALLOWED_CORS_ORIGINS", []
                ),
            },
        }
        return jsonify(config)

    data = request.get_json()
    # TODO: Implement configuration validation and database storage
    log_admin_action(current_user_id, "config_update", details=data)
    return jsonify({"message": "System configuration updated"})


# ---------------------------------------------------------------------------- #
#                               Admin Management                               #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/system/admins", methods=["GET", "POST"])
@jwt_required()
@role_required(UserRole.SUPER_ADMIN)
def manage_system_admins():
    current_user_id = get_jwt_identity()

    if request.method == "GET":
        admins = User.query.filter(
            User.role.in_([UserRole.SUPER_ADMIN, UserRole.SYSTEM_ADMIN])
        ).all()
        return jsonify({"admins": [admin.to_dict() for admin in admins]})

    data = request.get_json()
    error = validate_user_data(data, ["email", "password", "role"])
    if error:
        return jsonify({"error": error}), 400

    new_admin = User(
        email=data["email"],
        password_hash=generate_password_hash(data["password"]),
        role=data["role"],
        two_factor_enabled=True,
        full_name=data.get("full_name"),
        phone_number=data.get("phone_number"),
    )

    db.session.add(new_admin)
    db.session.commit()

    log_admin_action(current_user_id, "admin_created", {"admin_id": new_admin.id})
    return (
        jsonify(
            {"message": "Admin created successfully", "admin": new_admin.to_dict()}
        ),
        201,
    )


# ---------------------------------------------------------------------------- #
#                          System Audit and Monitoring                         #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/system/audit", methods=["GET"])
@jwt_required()
@role_required(UserRole.SUPER_ADMIN)
def system_audit():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    sensitive_operations = (
        AuthLog.query.filter(AuthLog.event_type.ilike("admin_%"))
        .order_by(desc(AuthLog.created_at))
        .paginate(page=page, per_page=per_page)
    )

    # Get system health metrics
    active_sessions = (
        db.session.query(db.func.count(User.id))
        .filter(User.last_login >= datetime.now() - timedelta(minutes=30))
        .scalar()
    )

    return jsonify(
        {
            "sensitive_operations": [
                {
                    "id": op.id,
                    "user_id": op.user_id,
                    "event_type": op.event_type,
                    "ip_address": op.ip_address,
                    "user_agent": op.user_agent,
                    "details": op.details,
                    "created_at": op.created_at.isoformat(),
                }
                for op in sensitive_operations.items
            ],
            "system_health": {
                "total_users": User.query.count(),
                "active_sessions": active_sessions,
                "failed_login_attempts_24h": AuthLog.query.filter(
                    and_(
                        AuthLog.event_type == "login",
                        AuthLog.status == "failure",
                        AuthLog.created_at >= datetime.utcnow() - timedelta(hours=24),
                    )
                ).count(),
                "system_load": {
                    "cpu_usage": "Get CPU usage",
                    "memory_usage": "Get memory usage",
                    "disk_usage": "Get disk usage",
                },
            },
            "total": sensitive_operations.total,
            "pages": sensitive_operations.pages,
            "current_page": sensitive_operations.page,
        }
    )


# ---------------------------------------------------------------------------- #
#                                   get users                                  #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/users", methods=["GET"])
@jwt_required()
@company_admin_or_higher
def get_users():
    current_user = User.query.get(get_jwt_identity())
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    search = request.args.get("search", "")

    query = User.query

    # Filter based on role permissions
    if current_user.role == UserRole.COMPANY_ADMIN:
        query = query.filter(User.company_id == current_user.company_id)
    elif current_user.role == UserRole.SYSTEM_ADMIN:
        # System admins can't see super admins
        query = query.filter(User.role != UserRole.SUPER_ADMIN)

    if search:
        query = query.filter(
            or_(User.email.ilike(f"%{search}%"), User.full_name.ilike(f"%{search}%"))
        )

    users = query.paginate(page=page, per_page=per_page)

    return jsonify(
        {
            "users": [user.to_dict() for user in users.items],
            "total": users.total,
            "pages": users.pages,
            "current_page": users.page,
        }
    )


# ---------------------------------------------------------------------------- #
#                                     create users                                    #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/users", methods=["POST"])
@jwt_required()
@role_required(UserRole.SYSTEM_ADMIN)
def create_user():
    data = request.get_json()
    required_fields = ["email", "password", "role"]

    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields"}), 400

    if User.query.filter_by(email=data["email"]).first():
        return jsonify({"error": "Email already registered"}), 409

    new_user = User(
        email=data["email"],
        password_hash=generate_password_hash(data["password"]),
        role=data["role"],
        full_name=data.get("full_name"),
        phone_number=data.get("phone_number"),
        company_id=data.get("company_id"),
        is_active=data.get("is_active", True),
    )

    db.session.add(new_user)
    db.session.commit()

    return (
        jsonify({"message": "User created successfully", "user": new_user.to_dict()}),
        201,
    )


# ---------------------------------------------------------------------------- #
#                                  update user                                 #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/users/<int:user_id>", methods=["PUT"])
@jwt_required()
@role_required(UserRole.SYSTEM_ADMIN)
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    updateable_fields = [
        "email",
        "full_name",
        "phone_number",
        "role",
        "is_active",
        "company_id",
        "two_factor_enabled",
    ]

    for field in updateable_fields:
        if field in data:
            setattr(user, field, data[field])

    if "password" in data:
        user.password_hash = generate_password_hash(data["password"])

    db.session.commit()
    return jsonify({"message": "User updated successfully", "user": user.to_dict()})


# ---------------------------------------------------------------------------- #
#                                  delete user                                 #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
@role_required(UserRole.SYSTEM_ADMIN)
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"})


# ---------------------------------------------------------------------------- #
#                                 users search                                 #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/users/search", methods=["GET"])
@jwt_required()
@company_admin_or_higher
def search_users():
    query = request.args.get("q", "")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    current_user = User.query.get(get_jwt_identity())
    base_query = User.query

    if current_user.role == UserRole.COMPANY_ADMIN:
        base_query = base_query.filter(User.company_id == current_user.company_id)
    elif current_user.role == UserRole.SYSTEM_ADMIN:
        base_query = base_query.filter(User.role != UserRole.SUPER_ADMIN)

    users = base_query.filter(
        or_(
            User.email.ilike(f"%{query}%"),
            User.full_name.ilike(f"%{query}%"),
            User.phone_number.ilike(f"%{query}%"),
        )
    ).paginate(page=page, per_page=per_page)

    return jsonify(
        {
            "users": [user.to_dict() for user in users.items],
            "total": users.total,
            "pages": users.pages,
            "current_page": users.page,
        }
    )


# ---------------------------------------------------------------------------- #
#                           logging endpoints                          #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/logs", methods=["GET"])
@jwt_required()
@role_required(UserRole.SYSTEM_ADMIN)
def get_logs():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    days = request.args.get("days", 90, type=int)
    event_type = request.args.get("event_type")
    status = request.args.get("status")
    user_id = request.args.get("user_id", type=int)
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")

    query = AuthLog.query

    # Apply filters
    if event_type:
        query = query.filter(AuthLog.event_type == event_type)
    if status:
        query = query.filter(AuthLog.status == status)
    if user_id:
        query = query.filter(AuthLog.user_id == user_id)

    if start_date:
        start = datetime.strptime(start_date, "%Y-%m-%d")
        query = query.filter(AuthLog.created_at >= start)
    if end_date:
        end = datetime.strptime(end_date, "%Y-%m-%d") + timedelta(days=1)
        query = query.filter(AuthLog.created_at < end)
    else:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(AuthLog.created_at >= cutoff_date)

    logs = query.order_by(desc(AuthLog.created_at)).paginate(
        page=page, per_page=per_page
    )

    return jsonify(
        {
            "logs": [
                {
                    "id": log.id,
                    "user_id": log.user_id,
                    "event_type": log.event_type,
                    "ip_address": log.ip_address,
                    "user_agent": log.user_agent,
                    "status": log.status,
                    "created_at": log.created_at.isoformat(),
                }
                for log in logs.items
            ],
            "total": logs.total,
            "pages": logs.pages,
            "current_page": logs.page,
        }
    )


# ---------------------------------------------------------------------------- #
#                              users bulk actions                              #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/users/bulk-action", methods=["POST"])
@jwt_required()
@role_required(UserRole.SYSTEM_ADMIN)
def bulk_user_action():
    data = request.get_json()
    if not data or "user_ids" not in data or "action" not in data:
        return jsonify({"error": "Missing required fields"}), 400

    user_ids = data["user_ids"]
    action = data["action"]
    current_user_id = get_jwt_identity()

    if action == "activate":
        User.query.filter(User.id.in_(user_ids)).update(
            {User.is_active: True}, synchronize_session=False
        )
    elif action == "deactivate":
        User.query.filter(User.id.in_(user_ids)).update(
            {User.is_active: False}, synchronize_session=False
        )
    elif action == "enable_2fa":
        User.query.filter(User.id.in_(user_ids)).update(
            {User.two_factor_enabled: True}, synchronize_session=False
        )
    else:
        return jsonify({"error": "Invalid action"}), 400

    db.session.commit()
    log_admin_action(current_user_id, f"bulk_{action}", {"user_ids": user_ids})
    return jsonify({"message": f"Bulk {action} completed successfully"})


# ---------------------------------------------------------------------------- #
#                            Analytics and Reporting                           #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/analytics/user-activity", methods=["GET"])
@jwt_required()
@role_required(UserRole.SYSTEM_ADMIN)
def get_user_activity():
    days = request.args.get("days", 30, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)

    # Get daily active users
    daily_active = (
        db.session.query(
            db.func.date(AuthLog.created_at),
            db.func.count(db.distinct(AuthLog.user_id)),
        )
        .filter(AuthLog.created_at >= start_date, AuthLog.event_type == "login")
        .group_by(db.func.date(AuthLog.created_at))
        .all()
    )

    # Get 2FA adoption rate
    total_users = User.query.count()
    users_with_2fa = User.query.filter_by(two_factor_enabled=True).count()

    return jsonify(
        {
            "daily_active_users": [
                {"date": str(date), "count": count} for date, count in daily_active
            ],
            "2fa_adoption_rate": (
                (users_with_2fa / total_users * 100) if total_users > 0 else 0
            ),
            "user_growth": {
                "total_users": total_users,
                "new_users": User.query.filter(User.created_at >= start_date).count(),
            },
        }
    )


# ---------------------------------------------------------------------------- #
#                                  log summary                                 #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/logs/summary", methods=["GET"])
@jwt_required()
@role_required(UserRole.SYSTEM_ADMIN)
def get_logs_summary():
    days = request.args.get("days", 90, type=int)
    cutoff_date = datetime.utcnow() - timedelta(days=days)

    # Get total counts
    total_logs = AuthLog.query.filter(AuthLog.created_at >= cutoff_date).count()
    failed_logins = AuthLog.query.filter(
        and_(
            AuthLog.created_at >= cutoff_date,
            AuthLog.event_type == "login",
            AuthLog.status == "failure",
        )
    ).count()

    # Get counts by event type
    event_counts = (
        db.session.query(AuthLog.event_type, db.func.count(AuthLog.id))
        .filter(AuthLog.created_at >= cutoff_date)
        .group_by(AuthLog.event_type)
        .all()
    )

    return jsonify(
        {
            "total_logs": total_logs,
            "failed_logins": failed_logins,
            "event_counts": dict(event_counts),
        }
    )


# ---------------------------------------------------------------------------- #
#                                     roles                                    #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/roles", methods=["GET"])
@jwt_required()
@role_required(UserRole.SYSTEM_ADMIN)
def get_available_roles():
    current_user = User.query.get(get_jwt_identity())

    available_roles = []
    if current_user.role == UserRole.SUPER_ADMIN.value:
        available_roles = [role.value for role in UserRole]
    elif current_user.role == UserRole.SYSTEM_ADMIN.value:
        available_roles = [UserRole.COMPANY_ADMIN.value, UserRole.USER.value]
    elif current_user.role == UserRole.COMPANY_ADMIN.value:
        available_roles = [UserRole.USER.value]

    return jsonify({"available_roles": available_roles})


# ---------------------------------------------------------------------------- #
#                               permission check                               #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/permissions/check", methods=["POST"])
@jwt_required()
def check_permissions():
    current_user = User.query.get(get_jwt_identity())
    data = request.get_json()

    if "required_role" not in data:
        return jsonify({"error": "Required role not specified"}), 400

    role_hierarchy = {
        UserRole.SUPER_ADMIN: 4,
        UserRole.SYSTEM_ADMIN: 3,
        UserRole.COMPANY_ADMIN: 2,
        UserRole.USER: 1,
    }

    user_role_level = role_hierarchy.get(current_user.role, 0)
    required_role_level = role_hierarchy.get(data["required_role"], 0)

    return jsonify({"has_permission": user_role_level >= required_role_level})


# ---------------------------------------------------------------------------- #
#                          System statistics endpoints                         #
# ---------------------------------------------------------------------------- #


@admin_bp.route("/statistics", methods=["GET"])
@jwt_required()
@role_required(UserRole.SYSTEM_ADMIN)
def get_statistics():
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active=True).count()
    total_companies = Company.query.count()
    users_with_2fa = User.query.filter_by(two_factor_enabled=True).count()

    # Get user registration trends (last 30 days)
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    new_users = User.query.filter(User.created_at >= thirty_days_ago).count()

    # Get authentication success rate (last 24 hours)
    last_24h = datetime.utcnow() - timedelta(hours=24)
    total_login_attempts = AuthLog.query.filter(
        and_(AuthLog.created_at >= last_24h, AuthLog.event_type == "login")
    ).count()

    successful_logins = AuthLog.query.filter(
        and_(
            AuthLog.created_at >= last_24h,
            AuthLog.event_type == "login",
            AuthLog.status == "success",
        )
    ).count()

    return jsonify(
        {
            "total_users": total_users,
            "active_users": active_users,
            "total_companies": total_companies,
            "users_with_2fa": users_with_2fa,
            "new_users_last_30_days": new_users,
            "login_success_rate_24h": (
                (successful_logins / total_login_attempts * 100)
                if total_login_attempts > 0
                else 0
            ),
            "total_login_attempts_24h": total_login_attempts,
        }
    )
