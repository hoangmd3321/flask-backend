import datetime
from time import strftime

from flask import jsonify, request
from marshmallow import fields, validate as validate_
from pytz import timezone

from app.enums import ALLOWED_EXTENSIONS_FILES
from app.enums import TIME_FORMAT_LOG, ALLOWED_EXTENSIONS_IMG
from .extensions import logger


def send_result(data: any = None, message: str = "OK", code: int = 200, version: int = 1, status: bool = True):
    """
    Args:
        data: simple result object like dict, string or list
        message: message send to client, default = OK
        code: code default = 200
        version: version of api
    :param data:
    :param message:
    :param code:
    :param version:
    :param status:
    :return:
    json rendered sting result
    """
    res = {
        "status": status,
        "code": code,
        "message": message,
        "data": data,
        "version": get_version(version)
    }

    return jsonify(res), 200


def send_error(data: any = None, message: str = "Error", code: int = 200, version: int = 1, status: bool = False):
    """

    :param data:
    :param message:
    :param code:
    :param version:
    :param status:
    :return:
    """
    res_error = {
        "status": status,
        "code": code,
        "message": message,
        "data": data,
        "version": get_version(version)
    }
    return jsonify(res_error), code


def get_version(version: int) -> str:
    """
    if version = 1, return api v1
    version = 2, return api v2
    Returns:

    """
    version_text = f"MayNo Website v{version}.0"
    return version_text


class FieldString(fields.String):
    """
    validate string field, max length = 1024
    Args:
        des:

    Returns:

    """
    DEFAULT_MAX_LENGTH = 1024  # 1 kB

    def __init__(self, validate=None, requirement=None, **metadata):
        """

        Args:
            validate:
            metadata:
        """
        if validate is None:
            validate = validate_.Length(max=self.DEFAULT_MAX_LENGTH)
        if requirement is not None:
            validate = validate_.NoneOf(error='Invalid input!', iterable={'full_name'})
        super(FieldString, self).__init__(validate=validate, required=requirement, **metadata)


class FieldNumber(fields.Number):
    """
    validate number field, max length = 30
    Args:
        des:

    Returns:

    """
    DEFAULT_MAX_LENGTH = 30  # 1 kB

    def __init__(self, validate=None, **metadata):
        """

        Args:
            validate:
            metadata:
        """
        if validate is None:
            validate = validate_.Length(max=self.DEFAULT_MAX_LENGTH)
        super(FieldNumber, self).__init__(validate=validate, **metadata)


def logged_input(json_req: str) -> None:
    """
    Logged input fields
    :param json_req:
    :return:
    """

    logger.info('%s %s %s %s %s INPUT FIELDS: %s',
                strftime(TIME_FORMAT_LOG),
                request.remote_addr,
                request.method,
                request.scheme,
                request.full_path,
                json_req)


def logged_error(error: str) -> None:
    """
    Logged input fields
    :param error:
    :return:
    """

    logger.info('%s %s %s %s %s ERROR: %s',
                strftime(TIME_FORMAT_LOG),
                request.remote_addr,
                request.method,
                request.scheme,
                request.full_path,
                error)


def allowed_file(filename: str) -> bool:
    """

    Args:
        filename:

    Returns:

    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_FILES

def allowed_file_img(filename):
    """

    Args:
        filename:

    Returns:

    """
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_IMG


def get_datetime_now() -> datetime:
    """
        Returns:
            current datetime
    """
    time_zon_sg = timezone('Asia/Saigon')
    return datetime.datetime.now(time_zon_sg)


def get_timestamp_now() -> int:
    """
        Returns:
            current time in timestamp
    """
    time_zon_sg = timezone('Asia/Saigon')
    return int(datetime.datetime.now(time_zon_sg).timestamp())


def is_password_contain_space(password: str) -> bool:
    """

    Args:
        password:

    Returns:
        True if password contain space
        False if password not contain space

    """
    return ' ' in password





def generate_product_code(index: int):
    """

    Args:
        index:

    Returns:

    """
    product_code = "SP{:04d}".format(index)
    return product_code
