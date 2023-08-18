
from functools import wraps

from flask import jsonify, request, make_response, session
from app.models import User
from app.utils import send_error
from flask_jwt_extended import (
    verify_jwt_in_request, get_jwt_claims, get_jwt_identity, verify_jwt_refresh_token_in_request
)
from flask_jwt_extended.exceptions import NoAuthorizationError


def authorization_require(refresh = False):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            try:
                verify_jwt_in_request() if refresh else verify_jwt_refresh_token_in_request()
            except NoAuthorizationError as ex:
                return send_error(message= str(ex), code= 401)
            except Exception as ex:
                return send_error(message= "Invalid token: " + str(ex), code=442)
            permission_route = "{0}@{1}".format(request.method.lower(), request.url_rule.rule)
            claims = get_jwt_claims()
            list_permission = claims["list_permission"]
            if permission_route in list_permission:
                return fn(*args, **kwargs)
            else:
                return send_error(message='You do not have permission')
        return decorator

    return wrapper




