import json
from flask import Flask
import os, sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from app.extensions import db
from app.models import User, Permission, Role, RolePermission, Group, GroupRole
from app.settings import DevConfig, ProdConfig, os

# CONFIG = DevConfig if os.environ.get('DevConfig') == '1' else ProdConfig
# default_file = "default.json" if os.environ.get('DevConfig') == '1' else "migrate/default.json"
CONFIG = DevConfig
default_file = "default.json"
default_rbac = "default_rbac.json"


class Worker:
    def __init__(self):
        app = Flask(__name__)

        app.config.from_object(CONFIG)
        db.app = app
        db.init_app(app)
        app_context = app.app_context()
        app_context.push()

        print("=" * 25, f"Starting migrate database on the uri: {CONFIG.SQLALCHEMY_DATABASE_URI}", "=" * 25)
        db.drop_all()  # drop all tables
        db.create_all()  # create a new schema

        with open(default_file, encoding='utf-8') as file:
            self.default_data = json.load(file)
        with open(default_rbac, encoding='utf-8') as file:
            self.default_rbac = json.load(file)

    def insert_rbac(self):
        permissions = self.default_rbac.get('permissions', {})
        for item in permissions:
            instance = Permission()
            for key in item.keys():
                instance.__setattr__(key, item[key])
            db.session.add(instance)
        db.session.commit()

        roles = self.default_rbac.get('roles', {})
        for item in roles:
            instance = Role()
            for key in item.keys():
                instance.__setattr__(key, item[key])
            db.session.add(instance)
        db.session.commit()

        role_permission = self.default_rbac.get('role_permission', {})
        for item in role_permission:
            instance = RolePermission()
            for key in item.keys():
                instance.__setattr__(key, item[key])
            db.session.add(instance)
        db.session.commit()

        groups = self.default_rbac.get('groups', {})
        for item in groups:
            instance = Group()
            for key in item.keys():
                instance.__setattr__(key, item[key])
            db.session.add(instance)
        db.session.commit()

        group_role = self.default_rbac.get('group_role', {})
        for item in group_role:
            instance = GroupRole()
            for key in item.keys():
                instance.__setattr__(key, item[key])
            db.session.add(instance)
        db.session.commit()

    def insert_default_users(self):
        users = self.default_data.get('users', {})
        for item in users:
            instance = User()
            for key in item.keys():
                instance.__setattr__(key, item[key])
            db.session.add(instance)

        db.session.commit()

    # def insert_default_categories(self):
    #     items = self.default_data.get('categories', {})
    #     for item in items:
    #         instance = Category()
    #         for key in item.keys():
    #             instance.__setattr__(key, item[key])
    #         db.session.add(instance)

    #     db.session.commit()

    # def insert_default_products(self):
    #     items = self.default_data.get('products', {})
    #     for item in items:
    #         instance = Product()
    #         for key in item.keys():
    #             instance.__setattr__(key, item[key])
    #         db.session.add(instance)

    #     db.session.commit()


if __name__ == '__main__':
    worker = Worker()
    worker.insert_rbac()
    worker.insert_default_users()
    # worker.insert_default_categories()
    # worker.insert_default_products()
    print("=" * 50, "Database migration completed", "=" * 50)
