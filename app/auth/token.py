# app/auth/tokens.py
from flask import current_app, jsonify, request
from flask_jwt_extended import create_access_token as jwt_create_access_token
from flask_jwt_extended import create_refresh_token as jwt_create_refresh_token
from datetime import datetime, timedelta
from ..models import User, AuthLog
from .. import db

def create_access_token(user_id, additional_claims=None):
    """
    Create a new access token for a user
    
    Args:
        user_id (int): The user's ID
        additional_claims (dict, optional): Additional claims to include in the token
        
    Returns:
        tuple: (access_token, refresh_token)
    """
    # Get the user
    user = User.query.get(user_id)
    if not user:
        raise ValueError("Invalid user_id")
    
    # Base claims that will be included in the token
    claims = {
        'user_id': user_id,
        'email': user.email,
        'role': user.role,
        'company_id': user.company_id
    }
    
    # Add any additional claims
    if additional_claims:
        claims.update(additional_claims)
    
    # Create the access token
    access_token = jwt_create_access_token(
        identity=user_id,
        additional_claims=claims,
        fresh=True
    )
    
    # Create the refresh token
    refresh_token = jwt_create_refresh_token(
        identity=user_id,
        additional_claims={'user_id': user_id}
    )
    
    # Update user's last login time
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    return access_token, refresh_token

def refresh_access_token(current_user_id):
    """
    Create a new access token using a refresh token
    
    Args:
        current_user_id (int): The current user's ID from the refresh token
        
    Returns:
        str: New access token
    """
    user = User.query.get(current_user_id)
    if not user:
        raise ValueError("Invalid user_id")
    
    claims = {
        'user_id': user.id,
        'email': user.email,
        'role': user.role,
        'company_id': user.company_id
    }
    
    return jwt_create_access_token(
        identity=user.id,
        additional_claims=claims,
        fresh=False
    )

