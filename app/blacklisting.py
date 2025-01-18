from datetime import datetime
from venv import logger
from flask import current_app
import redis
import os


def add_token_to_blacklist(jti, exp):
    """
    Add a token to the blacklist with strict type handling

    Args:
        jti (str): The JWT ID to blacklist
        exp (Union[int, float, str]): The expiration timestamp

    Returns:
        bool: True if blacklisting succeeded, False otherwise
    """
    try:
        # Input validation
        if not jti or not isinstance(jti, str):
            logger.error(f"Invalid JTI value: {jti}")
            return False

        # Convert expiration to timestamp
        try:
            if isinstance(exp, str):
                exp = float(exp)
            exp_timestamp = int(exp)
        except (ValueError, TypeError) as e:
            logger.error(f"Invalid expiration value {exp}: {str(e)}")
            return False

        # Calculate TTL
        current_timestamp = int(datetime.now().timestamp())
        ttl = max(1, exp_timestamp - current_timestamp)  # Minimum 1 second TTL

        # Use simple key-value storage with string value
        blacklist_key = f"blacklist_token_{jti}"

        # Store as a simple string flag
        success = redis_client.set(
            blacklist_key,
            "blacklisted",  # Using string instead of boolean/number
            ex=ttl,  # Set expiration in seconds
        )

        if success:
            logger.debug(f"Successfully blacklisted token {jti} with TTL {ttl}s")
            return True
        else:
            logger.error(f"Failed to set Redis key for token {jti}")
            return False

    except redis.RedisError as e:
        logger.error(f"Redis error while blacklisting token: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error while blacklisting token: {str(e)}")
        return False


def is_token_blacklisted(jti):
    """
    Check if a token is blacklisted

    Args:
        jti (str): The JWT ID to check

    Returns:
        bool: True if token is blacklisted or Redis is unavailable (fail-secure)
    """
    try:
        if not jti or not isinstance(jti, str):
            logger.error(f"Invalid JTI value in check: {jti}")
            return True  # Fail secure

        blacklist_key = f"blacklist_token_{jti}"
        return bool(redis_client.exists(blacklist_key))
    except redis.RedisError as e:
        logger.error(f"Redis error checking blacklist: {str(e)}")
        return True  # Fail secure - treat as blacklisted if Redis is down
    except Exception as e:
        logger.error(f"Unexpected error checking blacklist: {str(e)}")
        return True  # Fail secure


redis_client = redis.Redis(
    host=os.environ.get("REDIS_HOST", "localhost"),
    port=os.environ.get("REDIS_PORT", 6379),
    decode_responses=True,
    db=os.environ.get("REDIS_DB"),
    username=os.environ.get("REDIS_USERNAME"),
    password=os.environ.get("REDIS_PASSWORD"),
)
