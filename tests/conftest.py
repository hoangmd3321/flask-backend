import pytest
from app.app import create_app
from app.settings import TestConfig


@pytest.fixture(scope="module")
def app():
    """Create and configure a new app instance for each test."""
    # create the app with common test config
    app = create_app(TestConfig)

    yield app


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test runner for the app's Click commands."""
    return app.test_cli_runner()
