# logging.py contains functions for logging authentication events with detailed information for auditing and monitoring.
from datetime import datetime
from app.models import AuthLog, User


def log_auth_event(user_id, event_type, request, status):
    """
    Logs authentication events with detailed information for auditing and monitoring.

    Args:
        user_id (int): The ID of the user involved in the event (can be None for failed logins)
        event_type (str): Type of authentication event (login, logout, failed_login, 2fa_attempt)
        request (Request): Flask request object containing request information
        status (str): Outcome of the event ('success' or 'failure')
    """

    from app import db

    try:
        # Get IP address, considering potential proxy headers
        ip_address = request.headers.get("X-Forwarded-For", request.remote_addr)
        if ip_address:
            ip_address = ip_address.split(",")[0].strip()
            # Ensure IP address fits in the database field (varchar(45))
            ip_address = ip_address[:45]

        # Get user agent and ensure it fits in the database field (varchar(200))
        user_agent = request.headers.get("User-Agent", "Unknown")[:200]

        # Create new auth log entry matching the model schema
        auth_log = AuthLog(
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            # created_at will be automatically set by the model default
        )

        db.session.add(auth_log)
        db.session.commit()

        # If this was a successful login, update the user's last_login timestamp
        if event_type == "login" and status == "success" and user_id is not None:
            user = User.query.get(user_id)
            if user:
                user.last_login = datetime.now()
                db.session.commit()

    except Exception as e:
        # Log the error but don't raise it - logging shouldn't break authentication
        print(f"Error logging auth event: {str(e)}")
        db.session.rollback()
