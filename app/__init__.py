from datetime import timedelta
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from flask_bcrypt import Bcrypt
from flask_mail import Mail
import os
from dotenv import load_dotenv
from app.access import restrict_blueprint_access

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

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data["sub"]
        return User.query.get(identity)

    # Initialize JWT with additional error handlers
    @jwt.expired_token_loader
    def expired_token_callback(jwt_header, jwt_data):
        return jsonify({"error": "Token has expired", "code": "token_expired"}), 401

    @jwt.invalid_token_loader
    def invalid_token_callback(error):
        print(error)

        return jsonify({"error": "Invalid token", "code": "invalid_token"}), 401

    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return (
            jsonify(
                {"error": "Authorization token is missing", "code": "missing_token"}
            ),
            401,
        )

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

    # blueprint access restrictions
    # @app.before_request
    # @restrict_blueprint_access("admin_bp")
    # def restrict_admin():
    #     pass

    app.register_blueprint(auth_bp, url_prefix="/auth")
    app.register_blueprint(admin_bp, url_prefix="/admin")
    app.register_blueprint(company_bp, url_prefix="/company")
    app.register_blueprint(two_factor_bp, url_prefix="/two_factor")
    app.register_blueprint(service_bp, url_prefix="/service")

    # create database models
    with app.app_context():

        # delete and create all tables

        @app.before_request
        def create_db():

            db.create_all()

    @app.after_request
    def add_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        return response

    return app
