from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models import User, Company, AuthLog
from .. import db
from datetime import datetime, timedelta
from functools import wraps

admin_bp = Blueprint("admin", __name__)


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = User.query.get(get_jwt_identity())
        if not current_user or current_user.role != "admin":
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)

    return decorated_function


@admin_bp.route("/users", methods=["GET"])
@jwt_required()
@admin_required
def get_users():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    users = User.query.paginate(page=page, per_page=per_page)

    return jsonify(
        {
            "users": [
                {
                    "id": user.id,
                    "email": user.email,
                    "role": user.role,
                    "company_id": user.company_id,
                    "is_active": user.is_active,
                    "created_at": user.created_at.isoformat(),
                    "last_login": (
                        user.last_login.isoformat() if user.last_login else None
                    ),
                }
                for user in users.items
            ],
            "total": users.total,
            "pages": users.pages,
            "current_page": users.page,
        }
    )


@admin_bp.route("/users/<int:user_id>", methods=["PUT"])
@jwt_required()
@admin_required
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()

    if "role" in data:
        user.role = data["role"]
    if "is_active" in data:
        user.is_active = data["is_active"]
    if "company_id" in data:
        user.company_id = data["company_id"]

    db.session.commit()
    return jsonify({"message": "User updated successfully"})


@admin_bp.route("/logs", methods=["GET"])
@jwt_required()
@admin_required
def get_logs():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    days = request.args.get("days", 90, type=int)

    cutoff_date = datetime.utcnow() - timedelta(days=days)

    logs = (
        AuthLog.query.filter(AuthLog.created_at >= cutoff_date)
        .order_by(AuthLog.created_at.desc())
        .paginate(page=page, per_page=per_page)
    )

    return jsonify(
        {
            "logs": [
                {
                    "id": log.id,
                    "user_id": log.user_id,
                    "event_type": log.event_type,
                    "ip_address": log.ip_address,
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


@admin_bp.route("/companies", methods=["GET"])
@jwt_required()
@admin_required
def get_companies():
    companies = Company.query.all()
    return jsonify(
        {
            "companies": [
                {
                    "id": company.id,
                    "name": company.name,
                    "user_count": len(company.users),
                    "created_at": company.created_at.isoformat(),
                }
                for company in companies
            ]
        }
    )
