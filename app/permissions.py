from functools import wraps
from flask import jsonify, request
from flask_jwt_extended import get_jwt_identity
from sqlalchemy import Enum

from app.models import User


class UserRole(Enum):
    SUPER_ADMIN = "super_admin"  # System owners
    SYSTEM_ADMIN = "system_admin"  # Global system administrators
    COMPANY_ADMIN = "company_admin"  # Company-level administrators
    USER = "user"  # Regular users


class PermissionLevel(Enum):
    GLOBAL = "global"  # System-wide permissions
    COMPANY = "company"  # Company-level permissions
    USER = "user"  # User-level permissions


def role_required(minimum_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_user = User.query.get(get_jwt_identity())
            if not current_user:
                return jsonify({"error": "Authentication required"}), 401

            role_hierarchy = {
                UserRole.SUPER_ADMIN.value: 4,
                UserRole.SYSTEM_ADMIN.value: 3,
                UserRole.COMPANY_ADMIN.value: 2,
                UserRole.USER.value: 1,
            }

            user_role_level = role_hierarchy.get(current_user.role, 0)
            required_role_level = role_hierarchy.get(minimum_role.value, 0)

            if user_role_level < required_role_level:
                return jsonify({"error": "Insufficient permissions"}), 403

            return f(*args, **kwargs)

        return decorated_function

    return decorator


def company_admin_or_higher(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = User.query.get(get_jwt_identity())
        if not current_user:
            return jsonify({"error": "Authentication required"}), 401

        if current_user.role not in [
            UserRole.SUPER_ADMIN.value,
            UserRole.SYSTEM_ADMIN.value,
            UserRole.COMPANY_ADMIN.value,
        ]:
            return jsonify({"error": "Insufficient permissions"}), 403

        # For company admins, check if they're accessing their own company
        if current_user.role == UserRole.COMPANY_ADMIN.value:
            company_id = (
                kwargs.get("company_id")
                or request.args.get("company_id")
                or (request.get_json() or {}).get("company_id")
            )
            if company_id and int(company_id) != current_user.company_id:
                return jsonify({"error": "Access restricted to own company"}), 403

        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = User.query.get(get_jwt_identity())
        if not current_user or current_user.role != "admin":
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)

    return decorated_function
