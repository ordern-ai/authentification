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
