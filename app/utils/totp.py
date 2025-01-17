from secrets import token_bytes
import base64
from pyotp import TOTP


def generate_totp_secret(length: int = 32) -> str:
    """
    Generate a secure random secret for TOTP.

    Args:
        length (int): Length of the secret in bytes. Default is 32.

    Returns:
        str: Base32 encoded secret string
    """
    # Generate random bytes
    random_bytes = token_bytes(length)

    # Convert to base32 and remove padding
    base32_secret = base64.b32encode(random_bytes).decode("utf-8").rstrip("=")

    return base32_secret


def verify_totp(secret: str, token: str) -> bool:
    """
    Verify a TOTP token against a secret.

    Args:
        secret (str): The base32 encoded secret
        token (str): The TOTP token to verify

    Returns:
        bool: True if token is valid, False otherwise
    """
    totp = TOTP(secret)
    return totp.verify(token)
