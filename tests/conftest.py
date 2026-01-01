#!/usr/bin/env python3

import pytest
from csp_report_collector import create_app


# https://flask.palletsprojects.com/en/stable/testing/#fixtures
@pytest.fixture(scope="session")
def app():
    app = create_app(
        {
            "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
            "TESTING": True,
        }
    )

    yield app


@pytest.fixture(scope="session")
def db(app):
    with app.app_context():
        db = app.config["db"]

        assert db is not None

        yield db


@pytest.fixture(scope="session")
def client(app):
    with app.app_context():
        yield app.test_client()
