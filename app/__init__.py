from datetime import timedelta
from venv import logger
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_mail import Mail
import os
from dotenv import load_dotenv
from app.access import restrict_blueprint_access
from app.blacklisting import is_token_blacklisted, redis_client
from flask_jwt_extended.utils import decode_token


import logging

logging.basicConfig(level=logging.INFO)

# Load environment variables from .env file
load_dotenv()

db = SQLAlchemy()
jwt = JWTManager()
bcrypt = Bcrypt()
mail = Mail()


def create_app():
    app = Flask(__name__)

    # Configuration
    app.config.from_object("app.config.Config")

    # Initialize extensions after the app configuration
    db.init_app(app)
    bcrypt.init_app(app)
    mail.init_app(app)
    jwt.init_app(app)

    from app.models import User

    @jwt.token_in_blocklist_loader
    def check_if_token_is_revoked(jwt_header, jwt_payload):
        """Check if the token has been revoked"""
        try:
            jti = jwt_payload["jti"]
            token_in_redis = redis_client.get(f"blacklist_token:{jti}")

            return token_in_redis is not None
        except Exception as e:
            logger.error(f"Error checking token blacklist: {str(e)}")
            return True  # Fail secure - treat as blacklisted if Redis is down

    @jwt.revoked_token_loader
    def revoked_token_callback(jwt_header, jwt_payload):
        """Handle revoked/blacklisted token attempts"""
        return (
            jsonify({"error": "Token has been revoked", "code": "token_revoked"}),
            401,
        )

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.get(identity)

    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_data):
        return jsonify({"error": "Token has expired", "code": "token_expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        logger.error(f"Invalid token error: {error}")
        return jsonify({"error": "Invalid token", "code": "invalid_token"}), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return (
            jsonify(
                {"error": "Authorization token is missing", "code": "missing_token"}
            ),
            401,
        )

    @app.before_request
    def verify_jwt_in_request():
        """Check JWT token and blacklist status for protected routes"""
        # Skip token check for non-protected routes
        if request.endpoint and any(
            request.endpoint.startswith(prefix)
            for prefix in ["auth.login", "auth.register", "static"]
        ):
            return

        try:
            # Get the JWT from the request
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return

            token = auth_header.split(" ")[1]
            jwt_data = decode_token(token)

            # Check if token is blacklisted
            jti = jwt_data["jti"]

            if is_token_blacklisted(jti):
                return (
                    jsonify(
                        {"error": "Token has been revoked", "code": "token_revoked"}
                    ),
                    401,
                )

        except Exception as e:
            logger.error(f"Token verification error: {str(e)}")
            return jsonify({"error": "Invalid token", "code": "invalid_token"}), 401

    @app.errorhandler(403)
    def forbidden(e):
        return {
            "error": "Forbidden",
            "message": "Your IP is not authorized to access this resource",
        }, 403

    # Register blueprints
    from app.auth.routes import auth_bp
    from app.admin.routes import admin_bp
    from app.company.routes import company_bp
    from app.two_factor.routes import two_factor_bp
    from app.auth.service import service_bp

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(company_bp, url_prefix="/company")
    app.register_blueprint(two_factor_bp, url_prefix="/two_factor")
    app.register_blueprint(service_bp, url_prefix="/service")

    # Create database models
    with app.app_context():

        @app.before_request
        def create_db():
            db.create_all()

    @app.after_request
    def add_security_headers(response):
        response.headers.update(
            {
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            }
        )
        return response

    return app
