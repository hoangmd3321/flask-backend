# coding: utf-8
import uuid

from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

from app.enums import AVATAR_PATH_SEVER, DEFAULT_AVATAR
from app.extensions import db
from flask_jwt_extended import decode_token, get_jwt_identity, get_raw_jwt
from sqlalchemy.dialects.mysql import INTEGER
from app.utils import send_error, get_timestamp_now


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.String(50), primary_key=True)
    email = db.Column(db.String(100), nullable=False, unique=True)
    phone = db.Column(db.String(50), nullable=False, unique=True)
    password_hash = db.Column(db.String(255), nullable=False)
    gender = db.Column(db.Boolean, default=1)
    full_name = db.Column(db.String(100))
    address = db.Column(db.String(255))
    avatar_url = db.Column(db.String(255), default=AVATAR_PATH_SEVER + DEFAULT_AVATAR)
    date_of_birth = db.Column(db.String(50), default="01-01-1990")
    login_failed_attempts = db.Column(db.SmallInteger, default=0)
    force_change_password = db.Column(db.Boolean, default=0)
    created_date = db.Column(INTEGER(unsigned=True), default=get_timestamp_now(), index=True)
    modified_date = db.Column(INTEGER(unsigned=True), default=0)
    modified_date_password = db.Column(INTEGER(unsigned=True), default=get_timestamp_now())
    is_deleted = db.Column(db.Boolean, default=0)
    is_active = db.Column(db.Boolean, default=0)
    group_id = db.Column(ForeignKey('groups.id'), nullable=True, index=True)
    otp = db.Column(INTEGER(unsigned=True), default=None)
    otp_ttl = db.Column(INTEGER(unsigned=True), default=0)

    group = relationship('Group', primaryjoin='User.group_id == Group.id')

    def get_password_age(self):
        return int((get_timestamp_now() - self.modified_date_password) / 86400)

    @classmethod
    def get_all(cls, page=1, page_size=10):
        return cls.query.filter_by(is_deleted=False).order_by(cls.email) \
            .paginate(page=page, per_page=page_size, error_out=False).items

    def to_json(self):
        return {
            "id": self.id,
            "email": self.email,
            "full_name": self.full_name,
            "phone": self.phone,
            "date_of_birth": self.date_of_birth,
            "address": self.address,
            "gender": self.gender,
            "force_change_password": self.force_change_password,
            "created_date": self.created_date,
            "modified_date": self.modified_date,
            "avatar_url": self.avatar_url,
            "is_active": self.is_active,
            "is_deleted": self.is_deleted
        }

    @staticmethod
    def many_to_json(objects):
        items = []
        for o in objects:
            item = {
                "id": o.id,
                "email": o.email,
                "full_name": o.full_name,
                "phone": o.phone,
                "date_of_birth": o.date_of_birth,
                "address": o.address,
                "gender": o.gender,
                "force_change_password": o.force_change_password,
                "created_date": o.created_date,
                "modified_date": o.modified_date,
                "avatar_url": o.avatar_url,
                "is_active": o.is_active,
                "is_deleted": o.is_deleted
            }
            items.append(item)
        return items

    @classmethod
    def get_current_user(cls):
        return cls.query.get(get_jwt_identity())

    @classmethod
    def get_by_id(cls, _id):
        return cls.query.get(_id)


class Token(db.Model):
    __tablename__ = 'tokens'

    id = db.Column(db.String(50), primary_key=True)
    jti = db.Column(db.String(36), nullable=False)
    token_type = db.Column(db.String(10), nullable=False)
    user_identity = db.Column(db.String(50), nullable=False)
    revoked = db.Column(db.Boolean, nullable=False)
    expires = db.Column(INTEGER(unsigned=True), nullable=False)

    @staticmethod
    def add_token_to_database(encoded_token, user_identity):
        """
        Adds a new token to the database. It is not revoked when it is added.
        :param encoded_token:
        :param user_identity:
        """
        decoded_token = decode_token(encoded_token)
        jti = decoded_token['jti']
        token_type = decoded_token['type']
        expires = decoded_token['exp']
        revoked = False
        _id = str(uuid.uuid1())

        db_token = Token(
            id=_id,
            jti=jti,
            token_type=token_type,
            user_identity=user_identity,
            expires=expires,
            revoked=revoked,
        )
        db.session.add(db_token)
        db.session.commit()

    @staticmethod
    def is_token_revoked(decoded_token):
        """
        Checks if the given token is revoked or not. Because we are adding all the
        token that we create into this database, if the token is not present
        in the database we are going to consider it revoked, as we don't know where
        it was created.
        """
        jti = decoded_token['jti']
        token = Token.query.filter_by(jti=jti).first()
        if token:
            return token.revoked
        return True

    @staticmethod
    def revoke_token(jti):
        """
        Revokes the given token. Raises a TokenNotFound error if the token does
        not exist in the database
        """
        try:
            token = Token.query.filter_by(jti=jti).first()
            token.revoked = True
            db.session.commit()
        except Exception as ex:
            return send_error(message=str(ex))

    @staticmethod
    def revoke_all_token(users_identity):
        """
        Revokes the given token. Raises a TokenNotFound error if the token does
        not exist in the database.
        Set token Revoked flag is False to revoke this token.
        Args:
            users_identity: list or string, require
                list users id or user_id. Used to query all token of the user on the database
        """
        try:
            if type(users_identity) is not list:
                # convert user_id to list user_ids
                users_identity = [users_identity]

            tokens = Token.query.filter(Token.user_identity.in_(users_identity), Token.revoked == False).all()

            for token in tokens:
                token.revoked = True
            db.session.commit()
        except Exception as ex:
            return send_error(message=str(ex))

    @staticmethod
    def revoke_all_token2(users_identity):
        """
        Revokes all token of the given user except current token. Raises a TokenNotFound error if the token does
        not exist in the database.
        Set token Revoked flag is False to revoke this token.
        Args:
            users_identity: user id
        """
        jti = get_raw_jwt()['jti']
        try:
            tokens = Token.query.filter(Token.user_identity == users_identity, Token.revoked == False,
                                        Token.jti != jti).all()
            for token in tokens:
                token.revoked = True
            db.session.commit()
        except Exception as ex:
            return send_error(message=str(ex))

    @staticmethod
    def prune_database():
        """
        Delete tokens that have expired from the database.
        How (and if) you call this is entirely up you. You could expose it to an
        endpoint that only administrators could call, you could run it as a cron,
        set it up with flask cli, etc.
        """
        now_in_seconds = get_timestamp_now()
        Token.query.filter(Token.expires < now_in_seconds).delete()
        db.session.commit()


class Permission(db.Model):
    __tablename__ = 'permissions'

    id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=False)
    resource = db.Column(db.String(1000), nullable=False, unique=True)


class Role(db.Model):
    __tablename__ = 'roles'

    id = db.Column(db.String(50), primary_key=True)
    key = db.Column(db.String(100), nullable=False, unique=True)
    name = db.Column(db.String(100), nullable=False, unique=True)


class RolePermission(db.Model):
    __tablename__ = 'role_permission'

    id = db.Column(db.String(50), primary_key=True)
    role_id = db.Column(ForeignKey('roles.id'), nullable=False, index=True)
    permission_id = db.Column(ForeignKey('permissions.id'), nullable=False, index=True)

    permission = relationship('Permission', primaryjoin='RolePermission.permission_id == Permission.id')
    role = relationship('Role', primaryjoin='RolePermission.role_id == Role.id')


class GroupRole(db.Model):
    __tablename__ = 'group_role'

    id = db.Column(db.String(50), primary_key=True)
    role_id = db.Column(ForeignKey('roles.id'), nullable=False, index=True)
    group_id = db.Column(ForeignKey('groups.id'), nullable=False, index=True)

    group = relationship('Group', primaryjoin='GroupRole.group_id == Group.id')
    role = relationship('Role', primaryjoin='GroupRole.role_id == Role.id')


class Group(db.Model):
    __tablename__ = 'groups'

    id = db.Column(db.String(50), primary_key=True)
    key = db.Column(db.String(100), nullable=False, unique=True)
    name = db.Column(db.String(100), nullable=False, unique=True)


class Message(db.Model):
    __tablename__ = 'messages'

    id = db.Column(db.String(50), primary_key=True)
    descriptions = db.Column(db.String(255))
    toast = db.Column(db.Boolean, nullable=0)
    duration = db.Column(db.Integer, default=5)
    status = db.Column(db.String(20), default='success')


class MessageLanguage(db.Model):
    __tablename__ = 'message_language'

    id = db.Column(INTEGER(unsigned=True), primary_key=True)
    message_id = db.Column(ForeignKey('messages.id'), nullable=False, index=True)
    message = db.Column(db.String(255), nullable=False)
    language = db.Column(db.String(20), default='vi')

