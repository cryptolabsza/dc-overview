"""Shared fixtures for dc-overview tests."""

import os
import tempfile

import pytest


@pytest.fixture()
def app():
    """Create a fresh Flask app with an in-memory database for each test."""
    os.environ["DC_OVERVIEW_DATA"] = tempfile.mkdtemp()
    os.environ["SECRET_KEY"] = "test-secret"
    os.environ["SESSION_COOKIE_SECURE"] = "false"

    from dc_overview.app import app as flask_app, db

    flask_app.config.update(
        TESTING=True,
        WTF_CSRF_ENABLED=True,
        SQLALCHEMY_DATABASE_URI="sqlite:///:memory:",
    )

    with flask_app.app_context():
        db.create_all()
        yield flask_app
        db.drop_all()


@pytest.fixture()
def client(app):
    """Flask test client."""
    return app.test_client()


@pytest.fixture()
def auth_headers():
    """Headers that simulate an admin authenticated via fleet proxy."""
    return {
        "X-Fleet-Authenticated": "true",
        "X-Fleet-Auth-User": "testadmin",
        "X-Fleet-Auth-Role": "admin",
    }


@pytest.fixture()
def sample_server(app, client, auth_headers):
    """Create a sample server and return its id."""
    from dc_overview.app import db, Server

    with app.app_context():
        server = Server(name="test-server", server_ip="10.0.0.1")
        db.session.add(server)
        db.session.commit()
        return server.id
