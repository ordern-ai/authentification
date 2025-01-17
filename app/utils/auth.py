from flask import current_app, request
from app.logging import log_auth_event
from blacklisting import redis_client


def track_failed_attempts(user_id, ip_address):
    """Track failed login attempts"""
    key = f"failed_attempts:{ip_address}"
    pipe = redis_client.pipeline()

    pipe.incr(key)
    pipe.expire(key, 1800)  # 30 minutes

    result = pipe.execute()
    attempts = result[0]

    if attempts >= current_app.config.get("MAX_LOGIN_ATTEMPTS", 5):
        log_auth_event(user_id, "account_locked", request, "failure")
        return True

    return False


def validate_password_complexity(password):
    """Enhanced password validation"""
    if len(password) < 12:
        return False, "Password must be at least 12 characters long"

    if not any(c.isupper() for c in password):
        return False, "Password must contain at least one uppercase letter"

    if not any(c.islower() for c in password):
        return False, "Password must contain at least one lowercase letter"

    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number"

    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "Password must contain at least one special character"

    return True, ""
