import os

from flask import Blueprint, request
from flask_jwt_extended import jwt_required
from werkzeug.utils import secure_filename

from app.enums import FILE_PATH, URL_SERVER
from app.utils import send_result, send_error, allowed_file_img, get_timestamp_now
from app.validator import TypeValidation
from app.gateway import authorization_require

api = Blueprint('manage/images', __name__)


@api.route('', methods=['POST'])
@authorization_require()
def upload_image():
    """ This api for.

        Request Body:

        Returns:

        Examples::

    """

    _type = request.args.get('type', "", type=str).strip()

    # validate request params
    validator_type = TypeValidation()
    is_type_invalid = validator_type.validate({"type": _type})
    if is_type_invalid:
        return send_error(data=is_type_invalid, message='Please check your request params')

    try:
        image = request.files['image']
    except Exception as ex:
        return send_error(message=str(ex))

    if not allowed_file_img(image.filename):
        return send_error(message="Invalid image file")

    filename = image.filename
    filename = str(get_timestamp_now()) + filename
    filename = secure_filename(filename)

    path = os.path.join(FILE_PATH + f"{_type}/", filename)
    image_url = os.path.join(URL_SERVER + f"/{_type}/", filename)
    try:
        image.save(path)
    except Exception as ex:
        return send_error(message=str(ex))

    dt = {
        "image_url": image_url
    }

    return send_result(data=dt, message="Upload image successfully")
