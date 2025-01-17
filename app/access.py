from functools import wraps
from ipaddress import ip_address, ip_network
from flask import abort, current_app, request


BLUEPRINT_ACCESS = {
    "admin_bp": ["127.0.0.1", "10.0.0.1"],  # Admin blueprint
}


def restrict_blueprint_access(blueprint_name):
    """Decorator to check IP access for entire blueprint"""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if blueprint_name in BLUEPRINT_ACCESS:
                client_ip = ip_address(request.remote_addr)
                allowed = False

                for allowed_ip in BLUEPRINT_ACCESS[blueprint_name]:
                    try:
                        # Check if it's a network range
                        if "/" in allowed_ip:
                            if client_ip in ip_network(allowed_ip):
                                allowed = True
                                break
                        # Check if it's a single IP
                        elif client_ip == ip_address(allowed_ip):
                            allowed = True
                            break
                    except ValueError:
                        current_app.logger.error(f"Invalid IP or network: {allowed_ip}")

                if not allowed:
                    current_app.logger.warning(
                        f"Unauthorized access attempt to blueprint {blueprint_name} "
                        f"from {client_ip}"
                    )
                    abort(403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator
