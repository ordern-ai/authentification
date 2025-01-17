# app/auth/two_factor.py
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity
from twilio.rest import Client
from pyotp import TOTP
import smtplib
from email.mime.text import MIMEText
from ..models import User, AuthLog
from .. import db
import os

two_factor_bp = Blueprint('two_factor', __name__)

# Initialize Twilio client
twilio_client = Client(
    os.environ.get('TWILIO_ACCOUNT_SID'),
    os.environ.get('TWILIO_AUTH_TOKEN')
)

def generate_totp_secret():
    """Generate a new TOTP secret for authenticator apps"""
    return TOTP.random_base32()

def verify_totp_code(secret, code):
    """Verify a TOTP code against a secret"""
    totp = TOTP(secret)
    return totp.verify(code)

def send_email_code(email, code):
    """Send 2FA code via email"""
    msg = MIMEText(f'Your verification code is: {code}')
    msg['Subject'] = 'Two-Factor Authentication Code'
    msg['From'] = current_app.config['MAIL_DEFAULT_SENDER']
    msg['To'] = email
    
    with smtplib.SMTP(current_app.config['MAIL_SERVER']) as server:
        server.starttls()
        server.login(
            current_app.config['MAIL_USERNAME'],
            current_app.config['MAIL_PASSWORD']
        )
        server.send_message(msg)

def send_sms_code(phone_number, code):
    """Send 2FA code via SMS"""
    twilio_client.messages.create(
        body=f'Your verification code is: {code}',
        from_=os.environ.get('TWILIO_PHONE_NUMBER'),
        to=phone_number
    )

@two_factor_bp.route('/setup', methods=['POST'])
@jwt_required()
def setup_2fa():
    """Setup 2FA for a user"""
    current_user = User.query.get(get_jwt_identity())
    data = request.get_json()
    method = data.get('method')
    
    if method not in ['email', 'sms', 'authenticator']:
        return jsonify({'error': 'Invalid 2FA method'}), 400
    
    if method == 'authenticator':
        secret = generate_totp_secret()
        current_user.two_factor_secret = secret
        provisioning_uri = TOTP(secret).provisioning_uri(
            current_user.email,
            issuer_name="YourApp"
        )
    else:
        current_user.two_factor_secret = None
        provisioning_uri = None
    
    current_user.two_factor_method = method
    current_user.two_factor_enabled = True
    
    db.session.commit()
    
    response_data = {'message': '2FA setup successful'}
    if provisioning_uri:
        response_data['provisioning_uri'] = provisioning_uri
        response_data['secret'] = secret
    
    return jsonify(response_data)

@two_factor_bp.route('/verify', methods=['POST'])
def verify_2fa():
    """Verify 2FA code during login"""
    data = request.get_json()
    user_id = data.get('user_id')
    code = data.get('code')
    
    user = User.query.get(user_id)
    if not user or not user.two_factor_enabled:
        return jsonify({'error': 'Invalid request'}), 400
    
    verified = False
    if user.two_factor_method == 'authenticator':
        verified = verify_totp_code(user.two_factor_secret, code)
    else:
        # For email and SMS, verify against stored temporary code
        verified = code == user.two_factor_secret
    
    if verified:
        # Clear temporary code if using email/SMS
        if user.two_factor_method in ['email', 'sms']:
            user.two_factor_secret = None
            db.session.commit()
        
        # Create new auth log entry
        log = AuthLog(
            user_id=user.id,
            event_type='2fa_verification',
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string,
            status='success'
        )
        db.session.add(log)
        db.session.commit()
        
        # Generate new JWT tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        return jsonify({
            'access_token': access_token,
            'refresh_token': refresh_token
        })
    
    # Log failed attempt
    log = AuthLog(
        user_id=user.id,
        event_type='2fa_verification',
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string,
        status='failure'
    )
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'error': 'Invalid verification code'}), 401

@two_factor_bp.route('/disable', methods=['POST'])
@jwt_required()
def disable_2fa():
    """Disable 2FA for a user"""
    current_user = User.query.get(get_jwt_identity())
    
    current_user.two_factor_enabled = False
    current_user.two_factor_method = None
    current_user.two_factor_secret = None
    
    db.session.commit()
    
    return jsonify({'message': '2FA disabled successfully'})