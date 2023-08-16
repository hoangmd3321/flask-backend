from datetime import timedelta

from flask import Blueprint, request
from flask_jwt_extended import (create_access_token, create_refresh_token,
                                get_jwt_identity, get_raw_jwt)
from werkzeug.security import check_password_hash

from app.extensions import jwt, db
from app.gateway import authorization_require
from app.models import Token, User, GroupRole, RolePermission
from app.utils import send_result, send_error, logged_input, get_timestamp_now
from app.validator import AuthValidation, SendOTPValidation

ACCESS_EXPIRES = timedelta(days=10)
REFRESH_EXPIRES = timedelta(days=20)
api = Blueprint('auth', __name__)


def get_permissions(user: User):
    """
    get all permission of user login
    Args:
        user:

    Returns:
        permissions:
    """
    permissions = []
    group_id = user.group_id
    list_role = GroupRole.query.filter(GroupRole.group_id == group_id).all()
    for group_role in list_role:
        list_permission = RolePermission.query.filter(RolePermission.role_id == group_role.role_id).all()
        for role_permission in list_permission:
            if role_permission.permission.resource not in permissions:
                permissions.append(role_permission.permission.resource)

    return permissions


@api.route('/login', methods=['POST'])
def login():
    """
    This is controller of the login api

    Requests Body:
            email: string, require

            password: string, require
            phone: string, optional
            otp: string,optional

    Returns:
            {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'username': username
            }

    Examples::
        {
            "code": 200,
            "data": {
                "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MjU3Mjg1MTQsIm5iZiI6MTYyNTcyODUxNCwianRpIjoiODkzNDYwMjMtZTkyOS00YmM2LWIyMDktZWVlYzI2Yzg0OTA2IiwiZXhwIjoxNjI2NTkyNTE0LCJpZGVudGl0eSI6ImFkbWluIiwiZnJlc2giOmZhbHNlLCJ0eXBlIjoiYWNjZXNzIn0.qBSx-4u22a3zG2eJUKGhd714swX4zmLJ5WGCpQLzLQM",
                "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MjU3Mjg1MTQsIm5iZiI6MTYyNTcyODUxNCwianRpIjoiMGVhNWEzMzAtZmZhYi00Mzk3LTgzOWQtYzQ2Y2VlYjIzY2RkIiwiZXhwIjoxNjI3NDU2NTE0LCJpZGVudGl0eSI6ImFkbWluIiwidHlwZSI6InJlZnJlc2gifQ.qlM2GGju3k9d9J05t4qNu9iM_uqUdmf7DHB2MW1Tb24",
                "email": "admin"
            },
            "jsonrpc": "2.0",
            "message": "Logged in successfully!",
            "status": true,
            "version": "Mayno website v1.0"
        }

    """

    try:
        json_req = request.get_json()
    except Exception as ex:
        return send_error(message="Request Body incorrect json format: " + str(ex), code=442)

    logged_input(json_req)
    if json_req is None:
        return send_error(message='Please check your json requests', code=442)

    # trim input body
    json_body = {}
    for key, value in json_req.items():
        json_body.setdefault(key, str(value).strip())

    # validate request body
    validator_input = AuthValidation()
    is_not_validate = validator_input.validate(json_body)
    if is_not_validate:
        return send_error(data=is_not_validate, message='Please check your requests body')

    # Check username and password
    email = json_body.get("email")
    phone = json_body.get("phone")
    password = json_body.get("password")
    otp = json_body.get("otp")

    if email:
        user = User.query.filter_by(email=email).first()
    else:
        user = User.query.filter_by(phone=phone).first()
    if user is None:
        return send_error(message='Invalid email or password.\nPlease try again')

    if password and not check_password_hash(user.password_hash, password):
        return send_error(message='Invalid email or password.\nPlease try again')
    if otp and (str(user.otp) != otp or user.otp_ttl < get_timestamp_now()):
        return send_error(message='Invalid OTP.\nPlease try again')

    list_permission = get_permissions(user)
    access_token = create_access_token(identity=user.id, expires_delta=ACCESS_EXPIRES,
                                       user_claims={"list_permission": list_permission})
    refresh_token = create_refresh_token(identity=user.id, expires_delta=REFRESH_EXPIRES,
                                         user_claims={"list_permission": list_permission})

    # Store the tokens in our store with a status of not currently revoked.
    Token.add_token_to_database(access_token, user.id)
    Token.add_token_to_database(refresh_token, user.id)

    data: dict = user.to_json()
    data.setdefault('access_token', access_token)
    data.setdefault('refresh_token', refresh_token)

    return send_result(data=data, message="Logged in successfully!")


@api.route('/send_otp', methods=['POST'])
def send_otp():
    """
    This is controller of the send otp api

    Requests Body:
            phone: string, require

    Returns:
            {
                'access_token': access_token,
                'refresh_token': refresh_token,
                'username': username
            }

    Examples::
        {
            "code": 200,
            "data": {},
            "message": "Send OTP successfully!",
            "status": true,
            "version": "Mayno website v1.0"
        }

    """

    try:
        json_req = request.get_json()
    except Exception as ex:
        return send_error(message="Request Body incorrect json format: " + str(ex), code=442)

    logged_input(json_req)
    if json_req is None:
        return send_error(message='Please check your json requests', code=442)

    # trim input body
    json_body = {}
    for key, value in json_req.items():
        json_body.setdefault(key, str(value).strip())

    # validate request body
    validator_input = SendOTPValidation()
    is_not_validate = validator_input.validate(json_body)
    if is_not_validate:
        return send_error(data=is_not_validate, message='Please check your requests body')

    # Check username and password
    phone = json_body.get("phone")
    user = User.query.filter_by(phone=phone).first()
    if user is None:
        return send_error(message='Tài khoản không tồn tại. Vui lòng thử lại')

    # TODO: generate OTP code and send to user phone number
    # Default OTP 123456 and TTL = 1 minute
    user.otp = 123456
    user.otp_ttl = get_timestamp_now() + 60
    db.session.commit()

    return send_result(message="Một mã xác nhận đã được gửi đến điện thoại của bạn!")


@api.route('/refresh', methods=['POST'])
@authorization_require()
def refresh():
    """
    This api use for refresh expire time of the access token. Please inject the refresh token in Authorization header

    Requests Body:

        refresh_token: string,require
        The refresh token return in the login API

    Returns:

        access_token: string
        A new access_token

    Examples::

    """

    user_identity = get_jwt_identity()
    access_token = create_access_token(identity=user_identity, expires_delta=ACCESS_EXPIRES)

    # Store the tokens in our store with a status of not currently revoked.
    Token.add_token_to_database(access_token, user_identity)

    data = {
        'access_token': access_token
    }

    return send_result(data=data)


@api.route('/logout', methods=['DELETE'])
@authorization_require()
def logout():
    """
    This api logout current user, revoke current access token

    Examples::

    """

    jti = get_raw_jwt()['jti']
    Token.revoke_token(jti)  # revoke current token from database

    return send_result(message="Logout successfully!")


@jwt.token_in_blacklist_loader
def check_if_token_is_revoked(decrypted_token):
    """
    :param decrypted_token:
    :return:
    """
    return Token.is_token_revoked(decrypted_token)
