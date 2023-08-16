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

api = Blueprint('manage/users', __name__)


@api.route('', methods=['POST'])
@authorization_require()
def create_user():
    """ This is api for the user management registers user.

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

    # trim input body
    json_body = {}
    for key, value in json_req.items():
        if isinstance(value, str):
            json_body.setdefault(key, value.strip())
        else:
            json_body.setdefault(key, value)

    # validate request body
    validator_input = CreateUserValidation()
    is_not_validate = validator_input.validate(json_body)
    if is_not_validate:
        return send_error(data=is_not_validate, message='Please check your requests body')

    email = json_body.get("email")
    full_name = json_body.get("full_name")
    permission_group_id = json_body.get("permission_group_id")
    is_active: bool = json_body.get("is_active", False)

    duplicated_user = User.query.filter_by(email=email).first()
    if duplicated_user:
        return send_error(message="The email has existed!")
    password = ""
    created_date = get_timestamp_now()
    _id = str(uuid.uuid1())

    new_user = User(id=_id, email=email, password_hash=generate_password_hash(password),
                    created_date=created_date, is_active=is_active, full_name=full_name,
                    group_id=permission_group_id, modified_date_password=created_date)
    db.session.add(new_user)
    db.session.commit()

    return send_result(data=new_user.to_json(), message="Create user successfully!")


@api.route('/<user_id>', methods=['PUT'])
@authorization_require()
def update_user(user_id):
    """ This is api for the user management edit the user.

        Request Body:

        Returns:

        Examples::

    """

    user = User.get_by_id(user_id)
    if user is None:
        return send_error(message="Not found user!")

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
        if isinstance(value, str):
            json_body.setdefault(key, value.strip())
        else:
            json_body.setdefault(key, value)

    # validate request body
    # validator_input = CreateUserValidation()
    # is_not_validate = validator_input.validate(json_body)
    # if is_not_validate:
    #     return send_error(data=is_not_validate, message='Please check your requests body')

    for key, value in json_body.items():
        if key != "email":
            setattr(user, key, value)

    user.modified_date = get_timestamp_now()
    db.session.commit()

    return send_result(data=user.to_json(), message="Update user successfully!")


@api.route('/profile', methods=['PUT'])
@authorization_require()
def update_info():
    """ This is api for all user edit their profile.

        Request Body:

        Returns:


        Examples::

    """

    current_user = User.get_current_user()
    if current_user is None:
        return send_error(message="Not found user!")

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
        if key != "is_admin":
            if isinstance(value, str):
                json_body.setdefault(key, value.strip())
            else:
                json_body.setdefault(key, value)

    # validate request body
    # validator_input = AuthValidation()
    # is_not_validate = validator_input.validate(json_body)
    # if is_not_validate:
    #     return send_error(data=is_not_validate, message='Please check your requests body')

    avatar_url = json_body.get("avatar_url")
    if avatar_url is not None and avatar_url != current_user.avatar_url:
        old_image = current_user.avatar_url.split("/")[-1]
        if old_image != DEFAULT_AVATAR:
            try:
                os.remove(os.path.join(FILE_PATH + "avatars/", old_image))
            except Exception as ex:
                logged_error(str(ex))

    for key, value in json_body.items():
        if key != "email":
            setattr(current_user, key, value)

    current_user.modified_date = get_timestamp_now()
    db.session.commit()

    return send_result(data=current_user.to_json(), message="Update user successfully!")


@api.route('/password', methods=['PUT'])
@authorization_require()
def change_password():
    """ This api for all user change their password.

        Request Body:

        Returns:

        Examples::

    """

    current_user = User.get_current_user()

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
        if isinstance(value, str):
            json_body.setdefault(key, value.strip())
        else:
            json_body.setdefault(key, value)

    # validate request body
    validator_input = AuthValidation()
    is_not_validate = validator_input.validate(json_body)
    if is_not_validate:
        return send_error(data=is_not_validate, message='Please check your requests body')

    current_password = json_body.get("current_password")
    new_password = json_body.get("new_password")
    if not check_password_hash(current_user.password_hash, current_password):
        return send_error(message="Current password incorrect!")

    if is_password_contain_space(new_password):
        return send_error(message='Password cannot contain spaces')

    current_user.password_hash = generate_password_hash(new_password)
    current_user.modified_date_password = get_timestamp_now()
    db.session.commit()

    # revoke all token of current user  from database except current token
    Token.revoke_all_token2(get_jwt_identity())

    data = {
        "new_password": new_password,
        "current_password": current_password
    }

    return send_result(data=data, message="Change password successfully!")


@api.route('/<user_id>', methods=['DELETE'])
@authorization_require()
def delete_user(user_id):
    """ This api for the user management deletes the users.

        Returns:

        Examples::

    """
    user = User.get_by_id(user_id)

    db.session.delete(user)
    db.session.commit()

    # delete user avatar file
    old_image = user.avatar_url.split("/")[-1]
    if old_image != DEFAULT_AVATAR:
        try:
            os.remove(os.path.join(FILE_PATH + "avatars/", old_image))
        except Exception as ex:
            logged_error(str(ex))

    # revoke all token of reset user  from database
    Token.revoke_all_token(user_id)

    return send_result(message="Delete user successfully!")


@api.route('', methods=['GET'])
@authorization_require()
def get_all_users():
    """ This api gets all users.

        Returns:

        Examples::

    """

    page = request.args.get('page', 1, type=int)
    page_size = request.args.get('page_size', 10, type=int)
    text_search = request.args.get('search', "", type=str)

    text_search = "%{}%".format(text_search)
    total = User.query.filter((User.email.like(text_search) | User.full_name.like(text_search))).count()
    items = User.query.filter((User.email.like(text_search) | User.full_name.like(text_search))) \
        .order_by(User.created_date.desc()) \
        .paginate(page=page, per_page=page_size, error_out=False).items
    extra = 1 if (total % page_size) else 0
    total_pages = int(total / page_size) + extra
    results = {
        "items": User.many_to_json(items),
        "total": total,
        "total_pages": total_pages
    }

    return send_result(data=results)


@api.route('/<user_id>', methods=['GET'])
@authorization_require()
def get_user_by_id(user_id):
    """ This api get information of a user.

        Returns:

        Examples::

    """

    user = User.get_by_id(user_id)
    if user:
        user = user.to_json()
    return send_result(data=user)


@api.route('/profile', methods=['GET'])
@authorization_require()
def get_profile():
    """ This api for the user get their information.

        Returns:

        Examples::

    """

    current_user = User.get_current_user()
    if current_user:
        current_user = current_user.to_json()
    return send_result(data=current_user)
