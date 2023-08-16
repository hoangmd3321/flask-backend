import os
import uuid

from flask import Blueprint, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash

from app.enums import AVATAR_PATH_SEVER, DEFAULT_AVATAR, FILE_PATH
from app.extensions import db
from app.models import User, Token
from app.utils import send_result, send_error, logged_input, get_timestamp_now, is_password_contain_space, \
    logged_error
from app.validator import AuthValidation, CreateUserValidation
from app.gateway import authorization_require

api = Blueprint('manage/rbac', __name__)


@api.route('/refresh', methods=['PUT'])
# @authorization_require()
def refresh_rbac():
    """ This is api for the user management refresh role basic

        Request Body:

        Returns:

        Examples::
    """
    try:
        json_req = request.get_json()
    except Exception as ex:
        return send_error(message="Request Body incorrect json format: " + str(ex), code=442)

    logged_input(json_req)
    if json_req is None:
        return send_error(message='Please check your json requests', code=442)

    json_body = {}
    for key, value in json_req.items():
        json_body.setdefault(key, str(value).strip())

    permissions = json_body.get("permissions")


    # created_date = get_timestamp_now()
    # _id = str(uuid.uuid1())


    return send_result(data=permissions, message="Update rbac successfully!")