import pytest
from app.app import create_app
from app.settings import TestConfig
from app.models import User, Group, Role, Permission, RolePermission, GroupRole
from app.extensions import db
import json


default_user_file = "migrate/default.json"
default_rbac_file = "migrate/default_rbac.json"

def insert_rbac(default_rbac):
        permissions = default_rbac.get('permissions', {})
        for item in permissions:
            instance = Permission()
            for key in item.keys():
                instance.__setattr__(key, item[key])
            db.session.add(instance)
        db.session.commit()

        roles = default_rbac.get('roles', {})
        for item in roles:
            instance = Role()
            for key in item.keys():
                instance.__setattr__(key, item[key])
            db.session.add(instance)
        db.session.commit()

        role_permission = default_rbac.get('role_permission', {})
        for item in role_permission:
            instance = RolePermission()
            for key in item.keys():
                instance.__setattr__(key, item[key])
            db.session.add(instance)
        db.session.commit()

        groups = default_rbac.get('groups', {})
        for item in groups:
            instance = Group()
            for key in item.keys():
                instance.__setattr__(key, item[key])
            db.session.add(instance)
        db.session.commit()

        group_role = default_rbac.get('group_role', {})
        for item in group_role:
            instance = GroupRole()
            for key in item.keys():
                instance.__setattr__(key, item[key])
            db.session.add(instance)
        db.session.commit()


def insert_default_users(default_data):
        users = default_data.get('users', {})
        for item in users:
            instance = User()
            for key in item.keys():
                instance.__setattr__(key, item[key])
            db.session.add(instance)

        db.session.commit()

@pytest.fixture(scope="module")
def app():
    """Create and configure a new app instance for each test."""
    # create the app with common test config
    app = create_app(TestConfig)
    db.create_all()
    user_json = {}
    with open(default_user_file, encoding='utf-8') as file:
        user_json = json.load(file)
    with open(default_rbac_file, encoding='utf-8') as file:
        rbac_json = json.load(file)
    insert_default_users(user_json)
    insert_rbac(rbac_json)
    yield app

    db.drop_all()



@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test runner for the app's Click commands."""
    return app.test_cli_runner()

