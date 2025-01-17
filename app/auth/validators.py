import re
import phonenumbers


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


def validate_phone_number(phone_number):
    try:
        # Parse and validate phone number using phonenumbers library
        parsed_number = phonenumbers.parse(phone_number, None)
        return phonenumbers.is_valid_number(parsed_number)
    except Exception:
        return False
