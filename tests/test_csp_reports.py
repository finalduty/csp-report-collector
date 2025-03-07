import csp_reports
import csp_datamodel
import json
import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

@pytest.fixture
def empty():
    return ""

@pytest.fixture
def none():
    return None

@pytest.fixture(scope="module")
def legacy_report_type():
    return "csp-report"

@pytest.fixture(scope="module")
def report_type():
    return "csp-violation"

@pytest.fixture(scope="module")
def user_agent():
    return "Mozilla/5.0 - pytest"

@pytest.fixture(scope="module")
def document_url():
    return "https://pytest.test-domain.com/test"

@pytest.fixture(scope="module")
def blocked_url():
    return "https://www.evil.com/payload/evil.js"

@pytest.fixture(scope="module")
def effective_directive():
    return "inline-src"

@pytest.fixture(scope="module")
def original_policy():
    return "default-src 'self';"

@pytest.fixture(scope="module")
def referrer():
    return "https://www.duckduckgo.com"

@pytest.fixture(scope="module")
def source_file():
    return "https://my-domain.com/about"

@pytest.fixture(scope="module")
def disposition():
    return "enforce"

@pytest.fixture(scope="module")
def column_number():
    return "39"

@pytest.fixture(scope="module")
def line_number():
    return "17"

@pytest.fixture(scope="module")
def sample():
    return "<javascript>alert(1);</javascript>"

@pytest.fixture(scope="module")
def status_code():
    return "200"

@pytest.fixture(scope="function")
def get_db():
    engine = create_engine("sqlite:///:memory:")
    csp_datamodel.ReportsModel.metadata.create_all(engine)
    Session = sessionmaker(bind=engine,expire_on_commit=False)
    with Session() as db:
        yield db

def generate_report_to(*args) -> dict:
    report_to_keys = [
        "type",
        "user_agent",
        "url",
    ]
    report_to_body_keys = [
        "blockedURL",
        "documentURL",
        "effectiveDirective",
        "originalPolicy",
        "referrer",
        "disposition",
        "sourceFile",
        "columnNumber",
        "lineNumber",
        "sample",
        "statusCode"
    ]

    report_to = {}
    argc=0
    for key in report_to_keys:
        try:
            if args[argc] is not None:
                report_to[key] = args[argc]
        except KeyError:
            pass
        finally:
            argc+=1

    report_body = {}
    for key in report_to_body_keys:
        try:
            if args[argc] is not None:
                report_body[key] = args[argc]
        except KeyError:
            pass
        finally:
            argc+=1
    report_to["body"] = report_body

    return report_to

def generate_report_uri(*args) -> dict:
    report_uri_keys = [
        "blocked-uri",
        "document-uri",
        "disposition",
        "effective-directive",
        "violated-directive",
        "original-policy",
        "referrer",
        "script-sample",
        "status-code",
    ]
    if not args[0]:
        report_uri = {}
    else:
        report_uri = {args[0]:{}}
    argc = 1

    for key in report_uri_keys:
        try:
            if args[argc] is not None:
                if not args[0]:
                    report_uri[key] = args[argc]
                else:
                    report_uri[args[0]][key] = args[argc]
        except KeyError:
            pass
        finally:
            argc+=1

    return report_uri

@pytest.fixture(scope="function")
def report_to(report_type,user_agent, document_url, blocked_url, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, sample, status_code):
    return generate_report_to(report_type,user_agent, document_url, blocked_url, document_url, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, sample, status_code)

@pytest.fixture(scope="function")
def report_uri(legacy_report_type,blocked_url, document_url, disposition, effective_directive, original_policy, referrer, sample, status_code):
    return generate_report_uri(legacy_report_type,blocked_url, document_url, disposition, effective_directive, effective_directive, original_policy, referrer, sample, status_code)

def test_report_factory_reportto(report_to):
    print(f"report to: {report_to}")
    assert isinstance(csp_reports.get_report(report_to), csp_reports.ReportTo)

def test_report_factory_reporturi(report_uri):
    print(f"report uri: {report_uri}")
    assert isinstance(csp_reports.get_report(report_uri), csp_reports.ReportURI)

def test_write_database_legacy(report_uri,get_db):
    report = csp_reports.get_report(report_uri)
    db = get_db
    report.write(db)
    assert db.query(csp_datamodel.ReportsModel).count() == 1

def test_write_database(report_to,get_db):
    report = csp_reports.get_report(report_to)
    db = get_db
    report.write(db)
    assert db.query(csp_datamodel.ReportsModel).count() == 1

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
        "status_code"
    ],
    [
        pytest.param(none, blocked_url, document_url, disposition, effective_directive, effective_directive, original_policy, referrer, sample, status_code, id="missing-type"),
        pytest.param(legacy_report_type, none, document_url, disposition, effective_directive, effective_directive, original_policy, referrer, sample, status_code, id="missing-blocked-url"),
        pytest.param(legacy_report_type, blocked_url, none, disposition, effective_directive, effective_directive, original_policy, referrer, sample, status_code, id="missing-document-url"),
        pytest.param(legacy_report_type, blocked_url, document_url, none, effective_directive, effective_directive, original_policy, referrer, sample, status_code, id="missing-disposition"),
        pytest.param(legacy_report_type, blocked_url, document_url, disposition, none, none, original_policy, referrer, sample, status_code, id="missing-effective-directive"),
        pytest.param(legacy_report_type, blocked_url, document_url, disposition, effective_directive, effective_directive, none, referrer, sample, status_code, id="missing-policy"),
        pytest.param(legacy_report_type, blocked_url, document_url, disposition, effective_directive, effective_directive, original_policy, referrer, sample, none, id="missing-code"),
    ]
)
def test_validate_required_elements_legacy(legacy_report_type, blocked_url, document_url, disposition, effective_directive, violated_directive, original_policy, referrer, script, status_code):
    with pytest.raises(csp_reports.RequiredElementMissingError):
        report = csp_reports.get_report(generate_report_uri(legacy_report_type, blocked_url, document_url, disposition, effective_directive, violated_directive, original_policy, referrer, script, status_code))

@pytest.mark.parametrize(
    [
        "report_type",
        "user_agent",
        "url", 
        "blocked_url",
        "document_url",
        "effective_directive",
        "original_policy",
        "referrer",
        "disposition",
        "source_file",
        "column_number",
        "line_number",
        "sample",
        "status_code"
    ],
    [
        pytest.param(none, user_agent, document_url, blocked_url, document_url, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, sample, status_code, id="missing-type"),
        pytest.param(report_type, user_agent, document_url, none, document_url, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, sample, status_code, id="missing-blocked-url"),
        pytest.param(report_type, user_agent, document_url, blocked_url, none, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, sample, status_code, id="missing-document-url"),
        pytest.param(report_type, user_agent, document_url, blocked_url, document_url, effective_directive, original_policy, referrer, none, source_file, column_number, line_number, sample, status_code, id="missing-disposition"),
        pytest.param(report_type, user_agent, document_url, blocked_url, document_url, none, original_policy, referrer, disposition, source_file, column_number, line_number, sample, status_code, id="missing-effective-directive"),
        pytest.param(report_type, user_agent, document_url, blocked_url, document_url, effective_directive, none, referrer, disposition, source_file, column_number, line_number, sample, status_code, id="missing-policy"),
        pytest.param(report_type, user_agent, document_url, blocked_url, document_url, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, sample, none, id="missing-code"),
    ]
)
def test_validate_required_elements(report_type, user_agent, url, blocked_url, document_url, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, sample, status_code):
    with pytest.raises(csp_reports.RequiredElementMissingError):
        report = csp_reports.get_report(generate_report_to(report_type, user_agent, url, blocked_url, document_url, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, sample, status_code))

def test_invalid_report_type_legacy():
    with pytest.raises(csp_reports.InvalidReportType):
        invalid_report_type = "invalid-type"
        report = csp_reports.get_report(generate_report_uri(invalid_report_type,blocked_url, document_url, disposition, effective_directive, effective_directive, original_policy, referrer, sample, status_code))

def test_invalid_report_type():
    with pytest.raises(csp_reports.InvalidReportType):
        invalid_report_type = "invalid-type"
        report = csp_reports.get_report(generate_report_to(invalid_report_type, user_agent, document_url, blocked_url, document_url, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, sample, status_code))