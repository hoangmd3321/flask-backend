# -*- coding: utf-8 -*-

from time import strftime
from flask import Flask, request
from flask_cors import CORS
from app.extensions import logger, jwt, db
from .api import v1 as api_v1
from .enums import TIME_FORMAT_LOG
from .settings import ProdConfig
from .utils import send_error


def create_app(config_object=ProdConfig):
    """
    Init App
    :param config_object:
    :return:
    """
    app = Flask(__name__, static_url_path="", static_folder="./files")
    app.config.from_object(config_object)
    register_extensions(app)
    register_blueprints(app)
    register_monitor(app)
    CORS(app)

    return app


def register_extensions(app):
    """
    Init extension
    :param app:
    :return:
    """

    db.app = app
    db.init_app(app)  # SQLAlchemy
    jwt.init_app(app)

    @app.after_request
    def after_request(response):
        """

        :param response:
        :return:
        """
        # This IF avoids the duplication of registry in the log,
        # status code greater than 400 is already logged in @app.errorhandler.
        if 200 <= response.status_code < 400:
            ts = strftime(TIME_FORMAT_LOG)
            logger.error('%s %s %s %s %s %s',
                         ts,
                         request.remote_addr,
                         request.method,
                         request.scheme,
                         request.full_path,
                         response.status)
        return response

    @app.errorhandler(Exception)
    def exceptions(e):
        """
        Handling exceptions
        :param e:
        :return:
        """
        ts = strftime(TIME_FORMAT_LOG)
        error = '{} {} {} {} {} {}'.format(ts, request.remote_addr, request.method, request.scheme, request.full_path,
                                           str(e))
        logger.error(error)
        code = 500
        if hasattr(e, 'code'):
            code = e.code

        return send_error(message=str(e), code=code)

def register_monitor(app):

    from flask import Flask, url_for
    from app.utils import send_result

    def has_no_empty_params(rule):
        defaults = rule.defaults if rule.defaults is not None else ()
        arguments = rule.arguments if rule.arguments is not None else ()
        return len(defaults) >= len(arguments)

    @app.route("/api/v1/helper/site-map", methods=['GET'])
    def site_map():
        links = []
        for rule in app.url_map.iter_rules():
            # Filter out rules we can't navigate to in a browser
            # and rules that require parameters
            if has_no_empty_params(rule):
                object_method = dict()
                url = url_for(rule.endpoint, **(rule.defaults or {}))
                request_method = ""
                if "GET" in rule.methods:
                    request_method = "get"
                if "PUT" in rule.methods:
                    request_method = "put"
                if "POST" in rule.methods:
                    request_method = "post"
                if "DELETE" in rule.methods:
                    request_method = "delete"
                permission_route = "{0}@{1}".format(request_method.lower(), url)
                links.append(permission_route)

        return send_result(data=links, message="Logged in successfully!")


def register_blueprints(app):
    """
    Init blueprint for api url
    :param app:
    :return:
    """
    app.register_blueprint(api_v1.manage.rbac.api, url_prefix='/api/v1/manage/rbac')
    app.register_blueprint(api_v1.manage.user.api, url_prefix='/api/v1/manage/users')
    app.register_blueprint(api_v1.manage.image.api, url_prefix='/api/v1/manage/images')


    app.register_blueprint(api_v1.auth.api, url_prefix='/api/v1/auth')
    app.register_blueprint(api_v1.user.api, url_prefix='/api/v1/users')

