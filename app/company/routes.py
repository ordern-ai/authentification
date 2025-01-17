from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models import User, Company
from .. import db
from functools import wraps

company_bp = Blueprint("company", __name__)


def company_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = User.query.get(get_jwt_identity())
        if not current_user or current_user.role != "company_admin":
            return jsonify({"error": "Company admin privileges required"}), 403
        return f(*args, **kwargs)

    return decorated_function


@company_bp.route("/", methods=["POST"])
@jwt_required()
@company_admin_required
def create_company():
    data = request.get_json()

    company = Company(name=data["name"])

    db.session.add(company)
    db.session.commit()

    return (
        jsonify({"message": "Company created successfully", "company_id": company.id}),
        201,
    )


@company_bp.route("/<int:company_id>/users", methods=["GET"])
@jwt_required()
def get_company_users(company_id):
    current_user = User.query.get(get_jwt_identity())
    if not current_user or (
        current_user.role != "admin"
        and (
            current_user.company_id != company_id
            or current_user.role != "company_admin"
        )
    ):
        return jsonify({"error": "Unauthorized"}), 403

    users = User.query.filter_by(company_id=company_id).all()

    return jsonify(
        {
            "users": [
                {
                    "id": user.id,
                    "email": user.email,
                    "role": user.role,
                    "is_active": user.is_active,
                    "created_at": user.created_at.isoformat(),
                }
                for user in users
            ]
        }
    )


@company_bp.route("/<int:company_id>/users", methods=["POST"])
@jwt_required()
@company_admin_required
def add_company_user(company_id):
    current_user = User.query.get(get_jwt_identity())
    if current_user.company_id != company_id:
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json()

    user = User(
        email=data["email"],
        password_hash=data["password"],  # Note: Should be hashed before storing
        company_id=company_id,
        role="user",
    )

    db.session.add(user)
    db.session.commit()

    return (
        jsonify({"message": "User added to company successfully", "user_id": user.id}),
        201,
    )


@company_bp.route("/<int:company_id>/users/<int:user_id>", methods=["PUT"])
@jwt_required()
@company_admin_required
def update_company_user(company_id, user_id):
    current_user = User.query.get(get_jwt_identity())
    if current_user.company_id != company_id:
        return jsonify({"error": "Unauthorized"}), 403

    user = User.query.filter_by(id=user_id, company_id=company_id).first_or_404()
    data = request.get_json()

    if "role" in data and data["role"] != "admin":  # Prevent escalation to global admin
        user.role = data["role"]
    if "is_active" in data:
        user.is_active = data["is_active"]

    db.session.commit()
    return jsonify({"message": "User updated successfully"})


@company_bp.route("/<int:company_id>/settings", methods=["GET", "PUT"])
@jwt_required()
@company_admin_required
def company_settings(company_id):
    current_user = User.query.get(get_jwt_identity())
    if current_user.company_id != company_id:
        return jsonify({"error": "Unauthorized"}), 403

    company = Company.query.get_or_404(company_id)

    if request.method == "GET":
        return jsonify(
            {
                "id": company.id,
                "name": company.name,
                "created_at": company.created_at.isoformat(),
            }
        )

    data = request.get_json()
    if "name" in data:
        company.name = data["name"]

    db.session.commit()
    return jsonify({"message": "Company settings updated successfully"})
