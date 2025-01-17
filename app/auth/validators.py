import re


def validate_password(password):
    """
    Validate password strength
    Returns True if password meets requirements, False otherwise
    """
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"\d", password):
        return False
    return True


def validate_email(email):
    """
    Validate email format
    Returns True if email format is valid, False otherwise
    """
    return bool(re.match(r"[^@]+@[^@]+\.[^@]+", email))
