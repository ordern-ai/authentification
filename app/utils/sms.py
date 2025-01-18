from twilio.rest import Client
import os

# Initialize Twilio client
twilio_client = Client(
    os.environ.get("TWILIO_ACCOUNT_SID"), os.environ.get("TWILIO_AUTH_TOKEN")
)


def send_sms_code(phone_number, code):
    """Send 2FA code via SMS"""
    twilio_client.messages.create(
        body=f"Your verification code is: {code}",
        from_=os.environ.get("TWILIO_PHONE_NUMBER"),
        to=phone_number,
    )


# send message of supicious activity
def send_suspicious_activity(phone_number):
    """Send SMS alert of suspicious activity"""
    twilio_client.messages.create(
        body="Suspicious activity detected on your account. Please login to verify.",
        from_=os.environ.get("TWILIO_PHONE_NUMBER"),
        to=phone_number,
    )


# send message of new login
def send_new_login(phone_number):
    """Send SMS alert of new login"""
    twilio_client.messages.create(
        body="New login detected on your account. Please login to verify.",
        from_=os.environ.get("TWILIO_PHONE_NUMBER"),
        to=phone_number,
    )


# send message of password change
def send_password_change(phone_number):
    """Send SMS alert of password change"""
    twilio_client.messages.create(
        body="Password change detected on your account. Please login to verify.",
        from_=os.environ.get("TWILIO_PHONE_NUMBER"),
        to=phone_number,
    )


# send message of password reset
def send_password_reset(phone_number):
    """Send SMS alert of password reset"""
    twilio_client.messages.create(
        body="Password reset detected on your account. Please login to verify.",
        from_=os.environ.get("TWILIO_PHONE_NUMBER"),
        to=phone_number,
    )


