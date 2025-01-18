from flask import current_app
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

logger = logging.getLogger(__name__)


def send_email(to_email, subject, body, is_html=False):
    """
    Generic email sending function with proper error handling

    Args:
        to_email (str): Recipient email address
        subject (str): Email subject
        body (str): Email body content
        is_html (bool): Whether the body contains HTML content

    Returns:
        tuple: (success (bool), error_message (str or None))
    """
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = current_app.config["MAIL_DEFAULT_SENDER"]
        msg["To"] = to_email

        # Attach the body with the appropriate content type
        content_type = "html" if is_html else "plain"
        msg.attach(MIMEText(body, content_type))

        # Connect to SMTP server with error handling
        server = smtplib.SMTP(
            host=current_app.config["MAIL_SERVER"],
            port=current_app.config["MAIL_PORT"],
            timeout=current_app.config["MAIL_TIMEOUT"],
        )

        server.starttls()
        server.login(
            current_app.config["MAIL_USERNAME"], current_app.config["MAIL_PASSWORD"]
        )

        server.send_message(msg)
        server.quit()

        logger.info(f"Email sent successfully to {to_email}")
        return True, None

    except smtplib.SMTPAuthenticationError:
        error_msg = "SMTP Authentication failed. Check username and password."
        logger.error(error_msg)
        return False, error_msg

    except smtplib.SMTPServerDisconnected:
        error_msg = "SMTP Server disconnected. Check server settings."
        logger.error(error_msg)
        return False, error_msg

    except smtplib.SMTPException as e:
        error_msg = f"SMTP error occurred: {str(e)}"
        logger.error(error_msg)
        return False, error_msg

    except Exception as e:
        error_msg = f"Unexpected error sending email: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def send_email_code(email, code):
    """
    Send 2FA code via email

    Args:
        email (str): Recipient email address
        code (str): 2FA verification code

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    subject = "Two-Factor Authentication Code"
    body = f"""
    <html>
        <body>
            <h2>Your Verification Code</h2>
            <p>Your verification code is: <strong>{code}</strong></p>
            <p>This code will expire in 10 minutes.</p>
            <p>If you didn't request this code, please ignore this email.</p>
        </body>
    </html>
    """

    success, error = send_email(email, subject, body, is_html=True)
    if not success:
        logger.error(f"Failed to send 2FA code to {email}: {error}")
        raise Exception(f"Failed to send verification code: {error}")

    return success


def send_password_reset_email(email, token):
    """
    Send password reset email

    Args:
        email (str): Recipient email address
        token (str): Password reset token

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    reset_url = f"{current_app.config['FRONTEND_URL']}/reset-password?token={token}"

    subject = "Password Reset Request"
    body = f"""
    <html>
        <body>
            <h2>Password Reset Request</h2>
            <p>You have requested to reset your password. Click the link below to proceed:</p>
            <p><a href="{reset_url}">Reset Password</a></p>
            <p>This link will expire in 24 hours.</p>
            <p>If you didn't request this reset, please ignore this email.</p>
        </body>
    </html>
    """

    success, error = send_email(email, subject, body, is_html=True)
    if not success:
        logger.error(f"Failed to send password reset email to {email}: {error}")
        raise Exception(f"Failed to send password reset email: {error}")

    return success


def send_password_reset_email(user_email, reset_token):
    pass


def send_email_suspicous_activity(email):
    """
    Send email alert of suspicious activity

    Args:
        email (str): Recipient email address

    Returns:
        bool: True if email sent successfully, False otherwise
    """
    subject = "Suspicious Activity Detected"
    body = """
    <html>
        <body>
            <h2>Suspicious Activity Detected</h2>
            <p>We detected some suspicious activity on your account.</p>
            <p>If this was not you, please login to verify your account.</p>
        </body>
    </html>
    """

    success, error = send_email(email, subject, body, is_html=True)
    if not success:
        logger.error(f"Failed to send suspicious activity email to {email}: {error}")
        raise Exception(f"Failed to send suspicious activity email: {error}")

    return success
