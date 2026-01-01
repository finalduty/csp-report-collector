#!/usr/bin/env python3
## https://flask.palletsprojects.com/en/latest/testing/

from datetime import datetime, timezone

import pytest
from flask.testing import FlaskClient
from semver.version import Version

import csp_report_collector
from csp_report_collector import app, BaseModel


def default():
    """This function is intentionally blank so we can use it as a marker to replace default values with"""
    pass


@pytest.fixture(scope="session")
def sql_test_db():
    from flask_sqlalchemy import SQLAlchemy

    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    db = SQLAlchemy(model_class=BaseModel)
    db.init_app(app)

    with app.app_context():
        db.create_all()

    yield db


@pytest.fixture(autouse=True)
def client():
    with app.app_context():
        yield app.test_client()


def test__write_to_database(sql_test_db):
    csp_report = {
        "domain": "domain.evil",
        "blocked_uri": "https://domain.evil/",
        "document_uri": "https://domain.evil/",
        "reported_at": datetime.now(timezone.utc),
        "violated_directive": "frame-ancestors",
    }

    csp_report_collector._write_to_database(sql_test_db, **csp_report)

    assert sql_test_db.session.query(csp_report_collector.ReportsModel).count()


@pytest.mark.parametrize(
    "content_type,request_method,request_uri,blocked_uri,violated_directive,expected_status_code,expected_response",
    [
        pytest.param(default, default, default, default, default, 204, None, id="pass"),
        pytest.param(default, default, default, None, "script-src", 204, None, id="pass-eval"),
        pytest.param(default, default, default, None, "style-src", 204, None, id="pass-inline"),
        pytest.param(default, default, default, "about", default, 204, None, id="pass-about"),
        pytest.param("application/json", default, default, default, default, 400, {"error": "400 Bad Request: Invalid content type. Expected 'application/csp-report', got 'application/json'."}, id="invalid_content_type"),
        pytest.param(default, default, "/notfound", default, default, 404, {"error": "404 Not Found: The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again."}, id="not_found"),
        pytest.param(default, "GET", default, default, default, 405, {"error": "405 Method Not Allowed: The method is not allowed for the requested URL."}, id="method_not_allowed"),
    ],
)
def test_report_collector(client: FlaskClient, content_type, request_method, request_uri, blocked_uri, violated_directive, expected_status_code, expected_response):
    ## Set default values where required
    blocked_uri = "https://domain.evil" if blocked_uri == default else blocked_uri
    content_type = "application/csp-report" if content_type == default else content_type
    request_method = "POST" if request_method == default else request_method
    request_uri = "/" if request_uri == default else request_uri
    violated_directive = "frame-ancestors" if violated_directive == default else violated_directive

    data = {
        "csp-report": {
            "document-uri": "https://example.com/csp",
            "referrer": "",
            "violated-directive": violated_directive,
            "effective-directive": violated_directive,
            "original-policy": "frame-ancestors *.domain.net;",
            "disposition": "enforce",
            "blocked-uri": blocked_uri,
            "status-code": 0,
            "script-sample": "",
        }
    }
    headers = {"Content-Type": content_type}

    ## https://flask.palletsprojects.com/en/latest/testing/#tests-that-depend-on-an-active-context
    response = client.open(path=request_uri, method=request_method, headers=headers, json=data)

    assert response.status_code == expected_status_code
    assert response.content_type == "application/json"

    if expected_response is None:
        assert response.text == ""
    else:
        assert response.json == expected_response


def test_app_status(client: FlaskClient):
    response = client.get("/status")
    assert response._status_code == 200
    assert response.content_type == "text/html; charset=utf-8"
    assert response.text == "ok"


def test_version():
    ## https://python-semver.readthedocs.io/en/latest/usage/check-valid-semver-version.html
    assert Version.is_valid(csp_report_collector.__version__)


if __name__ == "__main__":
    pytest.main([__file__, "-vvv", "--no-cov"])
