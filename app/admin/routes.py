from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity
from ..models import User, Company, AuthLog
from .. import db
from datetime import datetime, timedelta
from functools import wraps
from sqlalchemy import and_, or_, desc
import pytz
from werkzeug.security import generate_password_hash

admin_bp = Blueprint("admin", __name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        current_user = User.query.get(get_jwt_identity())
        if not current_user or current_user.role != "admin":
            return jsonify({"error": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return decorated_function

# Enhanced user management endpoints
@admin_bp.route("/users", methods=["GET"])
@jwt_required()
@admin_required
def get_users():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    search = request.args.get("search", "")
    company_id = request.args.get("company_id", type=int)
    role = request.args.get("role")
    is_active = request.args.get("is_active", type=bool)
    
    query = User.query
    
    # Apply filters
    if search:
        query = query.filter(
            or_(
                User.email.ilike(f"%{search}%"),
                User.full_name.ilike(f"%{search}%")
            )
        )
    if company_id:
        query = query.filter(User.company_id == company_id)
    if role:
        query = query.filter(User.role == role)
    if is_active is not None:
        query = query.filter(User.is_active == is_active)

    users = query.paginate(page=page, per_page=per_page)
    
    return jsonify({
        "users": [user.to_dict() for user in users.items],
        "total": users.total,
        "pages": users.pages,
        "current_page": users.page
    })

@admin_bp.route("/users", methods=["POST"])
@jwt_required()
@admin_required
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
        is_active=data.get("is_active", True)
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "User created successfully", "user": new_user.to_dict()}), 201

@admin_bp.route("/users/<int:user_id>", methods=["PUT"])
@jwt_required()
@admin_required
def update_user(user_id):
    user = User.query.get_or_404(user_id)
    data = request.get_json()
    
    updateable_fields = [
        "email", "full_name", "phone_number", "role",
        "is_active", "company_id", "two_factor_enabled"
    ]
    
    for field in updateable_fields:
        if field in data:
            setattr(user, field, data[field])
            
    if "password" in data:
        user.password_hash = generate_password_hash(data["password"])
        
    db.session.commit()
    return jsonify({"message": "User updated successfully", "user": user.to_dict()})

@admin_bp.route("/users/<int:user_id>", methods=["DELETE"])
@jwt_required()
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"})

# Enhanced logging endpoints
@admin_bp.route("/logs", methods=["GET"])
@jwt_required()
@admin_required
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
    
    logs = query.order_by(desc(AuthLog.created_at)).paginate(page=page, per_page=per_page)
    
    return jsonify({
        "logs": [{
            "id": log.id,
            "user_id": log.user_id,
            "event_type": log.event_type,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "status": log.status,
            "created_at": log.created_at.isoformat()
        } for log in logs.items],
        "total": logs.total,
        "pages": logs.pages,
        "current_page": logs.page
    })

@admin_bp.route("/logs/summary", methods=["GET"])
@jwt_required()
@admin_required
def get_logs_summary():
    days = request.args.get("days", 90, type=int)
    cutoff_date = datetime.utcnow() - timedelta(days=days)
    
    # Get total counts
    total_logs = AuthLog.query.filter(AuthLog.created_at >= cutoff_date).count()
    failed_logins = AuthLog.query.filter(
        and_(
            AuthLog.created_at >= cutoff_date,
            AuthLog.event_type == "login",
            AuthLog.status == "failure"
        )
    ).count()
    
    # Get counts by event type
    event_counts = db.session.query(
        AuthLog.event_type,
        db.func.count(AuthLog.id)
    ).filter(
        AuthLog.created_at >= cutoff_date
    ).group_by(AuthLog.event_type).all()
    
    return jsonify({
        "total_logs": total_logs,
        "failed_logins": failed_logins,
        "event_counts": dict(event_counts)
    })

# Enhanced company management endpoints
@admin_bp.route("/companies", methods=["GET"])
@jwt_required()
@admin_required
def get_companies():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    search = request.args.get("search", "")
    
    query = Company.query
    
    if search:
        query = query.filter(Company.name.ilike(f"%{search}%"))
    
    companies = query.paginate(page=page, per_page=per_page)
    
    return jsonify({
        "companies": [{
            "id": company.id,
            "name": company.name,
            "user_count": len(company.users),
            "created_at": company.created_at.isoformat(),
            "active_users": len([u for u in company.users if u.is_active]),
            "users_with_2fa": len([u for u in company.users if u.two_factor_enabled])
        } for company in companies.items],
        "total": companies.total,
        "pages": companies.pages,
        "current_page": companies.page
    })

@admin_bp.route("/companies", methods=["POST"])
@jwt_required()
@admin_required
def create_company():
    data = request.get_json()
    
    if not data.get("name"):
        return jsonify({"error": "Company name is required"}), 400
        
    company = Company(name=data["name"])
    db.session.add(company)
    db.session.commit()
    
    return jsonify({
        "message": "Company created successfully",
        "company": {
            "id": company.id,
            "name": company.name,
            "created_at": company.created_at.isoformat()
        }
    }), 201

@admin_bp.route("/companies/<int:company_id>", methods=["PUT"])
@jwt_required()
@admin_required
def update_company(company_id):
    company = Company.query.get_or_404(company_id)
    data = request.get_json()
    
    if "name" in data:
        company.name = data["name"]
    
    db.session.commit()
    return jsonify({"message": "Company updated successfully"})

@admin_bp.route("/companies/<int:company_id>", methods=["DELETE"])
@jwt_required()
@admin_required
def delete_company(company_id):
    company = Company.query.get_or_404(company_id)
    
    # Check if company has users
    if company.users:
        return jsonify({
            "error": "Cannot delete company with existing users"
        }), 400
        
    db.session.delete(company)
    db.session.commit()
    return jsonify({"message": "Company deleted successfully"})

# System statistics endpoints
@admin_bp.route("/statistics", methods=["GET"])
@jwt_required()
@admin_required
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
        and_(
            AuthLog.created_at >= last_24h,
            AuthLog.event_type == "login"
        )
    ).count()
    
    successful_logins = AuthLog.query.filter(
        and_(
            AuthLog.created_at >= last_24h,
            AuthLog.event_type == "login",
            AuthLog.status == "success"
        )
    ).count()
    
    return jsonify({
        "total_users": total_users,
        "active_users": active_users,
        "total_companies": total_companies,
        "users_with_2fa": users_with_2fa,
        "new_users_last_30_days": new_users,
        "login_success_rate_24h": (successful_logins / total_login_attempts * 100) if total_login_attempts > 0 else 0,
        "total_login_attempts_24h": total_login_attempts
    })