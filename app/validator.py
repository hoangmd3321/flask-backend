from marshmallow import Schema, fields, validate, validates_schema, ValidationError

from app.enums import PENDING_CONFIRMATION, DELIVERING, SUCCESSFUL_DELIVERY, CANCELED


class InputValidation(Schema):
    """
    Validator and parser requests when suggests user right
    :param
        buchungskreis: string, required
        planstelle: string, required
        kostenstelle: string, required
    Ex:
    {
        "buchungskreis": "Schmitz Cargobull AG",
        "planstelle": "Leiter/in PMO / Business Development",
        "kostenstelle": "Vorstand"
    }
    """
    buchungskreis = fields.String(required=True, validate=validate.Length(min=1, max=255))
    planstelle = fields.String(required=True, validate=validate.Length(min=1, max=255))
    kostenstelle = fields.String(required=True, validate=validate.Length(min=1, max=255))


class TypeValidation(Schema):
    """
    Validator
    Ex:
    {
        "type": "avatars"
    }
    """
    type = fields.String(required=True,
                         validate=validate.OneOf(choices=["avatars", "category", "product", "article"],
                                                 error="Type must be [avatars, category, product or article]"))


class OrderStatusValidation(Schema):
    """
    Validator
    Ex:
    {
        "type": "avatars"
    }
    """
    status = fields.Number(required=True,
                           validate=validate.OneOf(
                               choices=[PENDING_CONFIRMATION, DELIVERING, SUCCESSFUL_DELIVERY, CANCELED],
                               error="Type must be "
                                     "[0 ~ PENDING_CONFIRMATION, 1 ~ DELIVERING, 2 ~ SUCCESSFUL_DELIVERY "
                                     "or 3 ~ CANCELED]"))


class IndexValidation(Schema):
    """
    Validator index user in excel file
    :param
        index: number
    Ex:
    {
        "index": 13
    }
    """
    index = fields.Number(required=True, validate=validate.Range(min=0, max=10000))


class AuthValidation(Schema):
    """
    Validator auth
    :param
        email: string, optional
        password: string, optional
        phone: string, optional
        otp: string, optional
    Ex:
    {
        "email": "admin@gmail.com",
        "password": "admin"
    }
    """
    email = fields.String(required=False, validate=validate.Length(min=1, max=50))
    password = fields.String(required=False, validate=validate.Length(min=1, max=32))
    phone = fields.String(required=False, validate=validate.Length(min=1, max=50))
    otp = fields.String(required=False, validate=validate.Length(min=1, max=6))

    @validates_schema
    def validate_multi_method(self, data, **kwargs):
        if data.get('phone', None):
            if not data.get('password', None) and not data.get('otp', None):
                raise ValidationError("Missing OTP or password fields")
        elif data.get('email', None):
            if not data.get('password', None):
                raise ValidationError("Missing password field")


class SendOTPValidation(Schema):
    """
    Validator auth
    :param
        phone: string, required
    Ex:
    {
        "phone": "84909323123"
    }
    """
    phone = fields.String(required=True, validate=validate.Length(min=1, max=50))


class CreateUserValidation(Schema):
    """
    Validator
    :param
        email: string, required
        password: string, required
        is_admin: bool, option
    Ex:
    {
        "email": "admin@gmail.com",
        "password": "admin",
        "is_admin": true
    }
    """
    email = fields.String(required=True, validate=validate.Length(min=1, max=50))
    full_name = fields.String(required=False, validate=validate.Length(min=1, max=100))
    avatar_url = fields.String(required=False, validate=validate.Length(max=255))
    password = fields.String(required=True, validate=validate.Length(min=4, max=32))
    is_admin = fields.Boolean(required=False)


class CommentValidation(Schema):
    user_id = fields.String(required=True)
    comment = fields.String(required=False)
    star = fields.Integer(required=True, validate=validate.Range(min=1, max=5))
    images_url = fields.String(required=False)
    product_id = fields.String(required=True)
