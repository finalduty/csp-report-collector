import csp_report_collector
import pytest

from flask.testing import FlaskClient
from semver.version import Version

from test_csp_reports import generate_report_to, generate_report_uri
from conftest import FixedData

@pytest.fixture()
def app():
    yield csp_report_collector.app

@pytest.fixture(autouse=True)
def client(app):
    with app.app_context():
        yield app.test_client()

@pytest.mark.parametrize(
    [
        "legacy_report_type",
        "blocked_url",
        "document_url",
        "disposition",
        "effective_directive",
        "violated_directive",
        "original_policy",
        "referrer",
        "script",
        "status_code",
        "content_type",
        "request_uri",
        "request_method",
        "expected_status_code",
        "expected_response"
    ],
    [
        pytest.param(FixedData.report_type("legacy"),FixedData.blocked_url(),FixedData.document_url(),FixedData.disposition(),FixedData.effective_directive(),FixedData.effective_directive(),FixedData.original_policy(),FixedData.referrer(),FixedData.code_sample(),FixedData.status_code(),FixedData.content_type("legacy"),FixedData.request_uri("submit"),"POST",204, FixedData.empty(), id="post-legacy-report"),
        pytest.param(FixedData.report_type("legacy"),FixedData.blocked_url(),FixedData.document_url(),FixedData.disposition(),FixedData.effective_directive(),FixedData.effective_directive(),FixedData.original_policy(),FixedData.referrer(),FixedData.code_sample(),FixedData.status_code(),FixedData.content_type("invalid"),FixedData.request_uri("submit"),"POST",400,'{"error":"400 Bad Request: Invalid content type. Expected one of application/csp-report application/reports+json, got \'text/html\'."}\n',id="invalid-content-type"),
        pytest.param(FixedData.report_type("legacy"),FixedData.blocked_url(),FixedData.document_url(),FixedData.disposition(),FixedData.effective_directive(),FixedData.effective_directive(),FixedData.original_policy(),FixedData.referrer(),FixedData.code_sample(),FixedData.status_code(),FixedData.content_type("legacy"),FixedData.request_uri("invalid"),"POST",404,'{"error":"404 Not Found: The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again."}\n',id="uri-not-found"),
        pytest.param(FixedData.report_type("legacy"),FixedData.blocked_url(),FixedData.document_url(),FixedData.disposition(),FixedData.effective_directive(),FixedData.effective_directive(),FixedData.original_policy(),FixedData.referrer(),FixedData.code_sample(),FixedData.status_code(),FixedData.content_type("legacy"),FixedData.request_uri("submit"),"GET",405,'{"error":"405 Method Not Allowed: The method is not allowed for the requested URL."}\n',id="method-not-allowed")
    ]
)
def test_receive_report_uri(client: FlaskClient, legacy_report_type, blocked_url, document_url, disposition, effective_directive, violated_directive, original_policy, referrer, script, status_code, content_type, request_uri, request_method, expected_status_code, expected_response):
    report = generate_report_uri(legacy_report_type, blocked_url, document_url, disposition, effective_directive, violated_directive, original_policy, referrer, script, status_code)
    headers = {"Content-Type": content_type}
    response = client.open(path=request_uri, method=request_method, headers=headers, json=report)
    assert response.content_type == "application/json"
    assert response.status_code == expected_status_code
    assert response.text == expected_response

def test_receive_report_to():
    pass

def test_view_reports():
    pass

def test_view_report_detail():
    pass

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