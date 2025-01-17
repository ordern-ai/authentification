import pytest
from flask import current_app
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
from pyotp import TOTP
from dotenv import load_dotenv


from app import create_app, db, bcrypt
from app.models import User, Company, AuthLog


@pytest.fixture(scope="session")
def app():
    """Create and configure a new app instance for the test session."""
    app = create_app()
    app.config.update(
        {
            "TESTING": True,
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "JWT_SECRET_KEY": "test-secret-key",
            "MAX_LOGIN_ATTEMPTS": 5,
            "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        }
    )

    return app


@pytest.fixture(scope="function")
def _db(app):
    """Create a new database for each test function."""
    with app.app_context():
        db.create_all()
        yield db
        db.session.remove()
        db.drop_all()


@pytest.fixture(scope="function")
def client(app):
    return app.test_client()


@pytest.fixture(scope="function")
def company(_db):
    """Create a test company."""
    company = Company(name="Test Company")
    _db.session.add(company)
    _db.session.commit()
    return company


@pytest.fixture(scope="function")
def test_user(app, _db, company):
    """Create a test user."""
    with app.app_context():
        user = User(
            email="test@example.com",
            password_hash=bcrypt.generate_password_hash("Password123").decode("utf-8"),
            company_id=company.id,
            role="user",
            is_active=True,
        )
        _db.session.add(user)
        _db.session.commit()
        return user


@pytest.fixture(scope="function")
def auth_headers(client, test_user):
    """Get authentication headers for a test user."""
    response = client.post(
        "/auth/login", json={"email": test_user.email, "password": "Password123"}
    )
    token = response.json["access_token"]
    return {"Authorization": f"Bearer {token}"}


class TestAuthentication:
    def test_register_success(self, client, company):
        """Test successful user registration"""
        response = client.post(
            "/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "Password123",
                "company_id": company.id,
            },
        )

        assert response.status_code == 201
        assert b"User registered successfully" in response.data

        # Verify user was created
        user = User.query.filter_by(email="newuser@example.com").first()
        assert user is not None
        assert user.company_id == company.id

    def test_register_invalid_password(self, client, company):
        """Test registration with weak password"""
        response = client.post(
            "/auth/register",
            json={
                "email": "newuser@example.com",
                "password": "weak",
                "company_id": company.id,
            },
        )

        assert response.status_code == 400
        assert b"Password must be at least 8 characters" in response.data

    def test_register_duplicate_email(self, client, test_user, company):
        """Test registration with existing email"""
        response = client.post(
            "/auth/register",
            json={
                "email": test_user.email,
                "password": "Password123",
                "company_id": company.id,
            },
        )

        assert response.status_code == 400
        assert b"Email already registered" in response.data

    def test_login_success(self, client, test_user):
        """Test successful login"""
        response = client.post(
            "/auth/login", json={"email": test_user.email, "password": "Password123"}
        )

        assert response.status_code == 200
        assert "access_token" in response.json
        assert "refresh_token" in response.json

    def test_login_invalid_credentials(self, client, test_user):
        """Test login with wrong password"""
        response = client.post(
            "/auth/login",
            json={"email": test_user.email, "password": "WrongPassword123"},
        )

        assert response.status_code == 401
        assert b"Invalid credentials" in response.data

    def test_login_account_lockout(self, client, test_user, app):
        """Test account lockout after multiple failed attempts"""
        # Configure max attempts
        app.config["MAX_LOGIN_ATTEMPTS"] = 3

        # Make multiple failed login attempts
        for _ in range(3):
            response = client.post(
                "/auth/login",
                json={"email": test_user.email, "password": "WrongPassword123"},
            )

        # Try one more time
        response = client.post(
            "/auth/login",
            json={
                "email": test_user.email,
                "password": "Password123",  # Correct password
            },
        )

        assert response.status_code == 403
        assert b"Account temporarily locked" in response.data

    def test_refresh_token(self, client, test_user):
        """Test refresh token endpoint"""
        # First login to get tokens
        response = client.post(
            "/auth/login", json={"email": test_user.email, "password": "Password123"}
        )

        refresh_token = response.json["refresh_token"]

        # Use refresh token to get new access token
        response = client.post(
            "/auth/refresh", headers={"Authorization": f"Bearer {refresh_token}"}
        )

        assert response.status_code == 200
        assert "access_token" in response.json

    def test_logout(self, client, test_user):
        """Test logout endpoint"""
        # First login to get token
        response = client.post(
            "/auth/login", json={"email": test_user.email, "password": "Password123"}
        )

        access_token = response.json["access_token"]

        # Logout
        response = client.post(
            "/auth/logout", headers={"Authorization": f"Bearer {access_token}"}
        )

        assert response.status_code == 200
        assert b"Successfully logged out" in response.data


class TestTwoFactorAuth:
    @pytest.fixture
    def auth_headers(self, client, test_user):
        """Get authentication headers for a test user"""
        response = client.post(
            "/auth/login", json={"email": test_user.email, "password": "Password123"}
        )
        token = response.json["access_token"]
        return {"Authorization": f"Bearer {token}"}

    def test_setup_2fa_authenticator(self, client, test_user, auth_headers):
        """Test setting up 2FA with authenticator app"""
        response = client.post(
            "/auth/two-factor/setup",
            json={"method": "authenticator"},
            headers=auth_headers,
        )

        assert response.status_code == 200
        assert "provisioning_uri" in response.json
        assert "secret" in response.json

        # Verify user's 2FA settings
        user = User.query.get(test_user.id)
        assert user.two_factor_enabled
        assert user.two_factor_method == "authenticator"
        assert user.two_factor_secret is not None

    @patch("app.auth.two_factor.send_email_code")
    def test_setup_2fa_email(self, mock_send_email, client, test_user, auth_headers):
        """Test setting up 2FA with email"""
        response = client.post(
            "/auth/two-factor/setup", json={"method": "email"}, headers=auth_headers
        )

        assert response.status_code == 200
        assert mock_send_email.called

        user = User.query.get(test_user.id)
        assert user.two_factor_enabled
        assert user.two_factor_method == "email"

    def test_verify_2fa_authenticator(self, client, test_user):
        """Test verifying 2FA code with authenticator"""
        # Setup 2FA first
        secret = TOTP.random_base32()
        test_user.two_factor_enabled = True
        test_user.two_factor_method = "authenticator"
        test_user.two_factor_secret = secret
        db.session.commit()

        # Generate valid TOTP code
        totp = TOTP(secret)
        valid_code = totp.now()

        response = client.post(
            "/auth/two-factor/verify",
            json={"user_id": test_user.id, "code": valid_code},
        )

        assert response.status_code == 200
        assert "access_token" in response.json
        assert "refresh_token" in response.json

    def test_disable_2fa(self, client, test_user, auth_headers):
        """Test disabling 2FA"""
        # Enable 2FA first
        test_user.two_factor_enabled = True
        test_user.two_factor_method = "authenticator"
        test_user.two_factor_secret = "secret"
        db.session.commit()

        response = client.post("/auth/two-factor/disable", headers=auth_headers)

        assert response.status_code == 200

        user = User.query.get(test_user.id)
        assert not user.two_factor_enabled
        assert user.two_factor_method is None
        assert user.two_factor_secret is None
