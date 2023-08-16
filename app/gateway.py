
from functools import wraps

from flask import jsonify, request, make_response, session
from app.models import User
from app.utils import send_error
from flask_jwt_extended import (
    verify_jwt_in_request, get_jwt_claims, get_jwt_identity
)


def authorization_require():
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            verify_jwt_in_request()
            permission_route = "{0}@{1}".format(request.method.lower(), request.url_rule.rule)
            claims = get_jwt_claims()
            list_permission = claims["list_permission"]
            if permission_route in list_permission:
                return fn(*args, **kwargs)
            else:
                return send_error(message='You do not have permission')
        return decorator

    return wrapper
