import datetime
from flask import current_app
import redis


def add_token_to_blacklist(jti, exp):
    """Add a token to the blacklist"""
    redis_client.setex(f'blacklist_token_{jti}', exp - datetime.now().timestamp(), 'true')

def is_token_blacklisted(jti):
    """Check if a token is blacklisted"""
    return redis_client.exists(f'blacklist_token_{jti}')



redis_client = redis.Redis(
    host=current_app.config.get('REDIS_HOST', 'localhost'),
    port=current_app.config.get('REDIS_PORT', 6379),
    db=current_app.config.get('REDIS_DB', 0)
)