import csp_reports
import csp_datamodel
import pytest

from conftest import FixedData

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
def report_to():
    return generate_report_to(
        FixedData.report_type("preferred"),
        FixedData.user_agent(),
        FixedData.document_url(),
        FixedData.blocked_url(),
        FixedData.document_url(), 
        FixedData.effective_directive(),
        FixedData.original_policy(),
        FixedData.referrer(),
        FixedData.disposition(),
        FixedData.source_file(),
        FixedData.column_number(),
        FixedData.line_number(),
        FixedData.code_sample(),
        FixedData.status_code()
    )

@pytest.fixture(scope="function")
def report_uri():
    return generate_report_uri(
        FixedData.report_type("legacy"),
        FixedData.blocked_url(),
        FixedData.document_url(),
        FixedData.disposition(),
        FixedData.effective_directive(),
        FixedData.effective_directive(),
        FixedData.original_policy(),
        FixedData.referrer(),
        FixedData.code_sample(),
        FixedData.status_code()
    )

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
        pytest.param(FixedData.none(), FixedData.blocked_url(), FixedData.document_url(), FixedData.disposition(), FixedData.effective_directive(), FixedData.effective_directive(), FixedData.original_policy(), FixedData.referrer(), FixedData.code_sample(), FixedData.status_code(), id="missing-type"),
        pytest.param(FixedData.report_type("legacy"), FixedData.blocked_url(), FixedData.none(), FixedData.disposition(), FixedData.effective_directive(), FixedData.effective_directive(), FixedData.original_policy(), FixedData.referrer(), FixedData.code_sample(), FixedData.status_code(), id="missing-document-url"),
        pytest.param(FixedData.report_type("legacy"), FixedData.blocked_url(), FixedData.document_url(), FixedData.none(), FixedData.effective_directive(), FixedData.effective_directive(), FixedData.original_policy(), FixedData.referrer(), FixedData.code_sample(), FixedData.status_code(), id="missing-disposition"),
        pytest.param(FixedData.report_type("legacy"), FixedData.blocked_url(), FixedData.document_url(), FixedData.disposition(), FixedData.none(), FixedData.none(), FixedData.original_policy(), FixedData.referrer(), FixedData.code_sample(), FixedData.status_code(), id="missing-effective-directive"),
        pytest.param(FixedData.report_type("legacy"), FixedData.blocked_url(), FixedData.document_url(), FixedData.disposition(), FixedData.effective_directive(), FixedData.effective_directive(), FixedData.none(), FixedData.referrer(), FixedData.code_sample(), FixedData.status_code(), id="missing-policy"),
        pytest.param(FixedData.report_type("legacy"), FixedData.blocked_url(), FixedData.document_url(), FixedData.disposition(), FixedData.effective_directive(), FixedData.effective_directive(), FixedData.original_policy(), FixedData.referrer(), FixedData.code_sample(), FixedData.none(), id="missing-code"),
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
        "script",
        "status_code"
    ],
    [
        pytest.param(FixedData.none(), FixedData.user_agent(), FixedData.document_url(), FixedData.blocked_url(), FixedData.document_url(), FixedData.effective_directive(), FixedData.original_policy(), FixedData.referrer(), FixedData.disposition(), FixedData.source_file(), FixedData.column_number(), FixedData.line_number(), FixedData.code_sample(), FixedData.status_code(), id="missing-type"),
        pytest.param(FixedData.report_type("preferred"), FixedData.user_agent(), FixedData.document_url(), FixedData.blocked_url(), FixedData.none(), FixedData.effective_directive(), FixedData.original_policy(), FixedData.referrer(), FixedData.disposition(), FixedData.source_file(), FixedData.column_number(), FixedData.line_number(), FixedData.code_sample(), FixedData.status_code(), id="missing-document-url"),
        pytest.param(FixedData.report_type("preferred"), FixedData.user_agent(), FixedData.document_url(), FixedData.blocked_url(), FixedData.document_url(), FixedData.effective_directive(), FixedData.original_policy(), FixedData.referrer(), FixedData.none(), FixedData.source_file(), FixedData.column_number(), FixedData.line_number(), FixedData.code_sample(), FixedData.status_code(), id="missing-disposition"),
        pytest.param(FixedData.report_type("preferred"), FixedData.user_agent(), FixedData.document_url(), FixedData.blocked_url(), FixedData.document_url(), FixedData.none(), FixedData.original_policy(), FixedData.referrer(), FixedData.disposition(), FixedData.source_file(), FixedData.column_number(), FixedData.line_number(), FixedData.code_sample(), FixedData.status_code(), id="missing-effective-directive"),
        pytest.param(FixedData.report_type("preferred"), FixedData.user_agent(), FixedData.document_url(), FixedData.blocked_url(), FixedData.document_url(), FixedData.effective_directive(), FixedData.none(), FixedData.referrer(), FixedData.disposition(), FixedData.source_file(), FixedData.column_number(), FixedData.line_number(), FixedData.code_sample(), FixedData.status_code(), id="missing-policy"),
        pytest.param(FixedData.report_type("preferred"), FixedData.user_agent(), FixedData.document_url(), FixedData.blocked_url(), FixedData.document_url(), FixedData.effective_directive(), FixedData.original_policy(), FixedData.referrer(), FixedData.disposition(), FixedData.source_file(), FixedData.column_number(), FixedData.line_number(), FixedData.code_sample(), FixedData.none(), id="missing-code"),
    ]
)
def test_validate_required_elements(report_type, user_agent, url, blocked_url, document_url, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, script, status_code):
    with pytest.raises(csp_reports.RequiredElementMissingError):
        report = csp_reports.get_report(generate_report_to(report_type, user_agent, url, blocked_url, document_url, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, script, status_code))

@pytest.mark.parametrize(
    [
        "document_url",
        "blocked_url",
        "disposition",
        "effective_directive",
        "original_policy",
        "referrer",
        "sample",
        "status_code"
    ],
    [
        (FixedData.document_url(), FixedData.blocked_url(), FixedData.disposition(), FixedData.effective_directive(), FixedData.original_policy(), FixedData.referrer(), FixedData.code_sample(), FixedData.status_code())
    ]
)
def test_invalid_report_type_legacy(document_url, blocked_url, disposition, effective_directive, original_policy, referrer, sample, status_code):
    with pytest.raises(csp_reports.InvalidReportType):
        invalid_report_type = "invalid-type"
        report = csp_reports.get_report(generate_report_uri(invalid_report_type,blocked_url, document_url, disposition, effective_directive, effective_directive, original_policy, referrer, sample, status_code))

@pytest.mark.parametrize(
        [
            "user_agent",
            "document_url",
            "blocked_url",
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
            (FixedData.user_agent(), FixedData.document_url(), FixedData.blocked_url(), FixedData.effective_directive(), FixedData.original_policy(), FixedData.referrer(), FixedData.disposition(), FixedData.source_file(), FixedData.column_number(), FixedData.line_number(), FixedData.code_sample(), FixedData.status_code())
        ]
)
def test_invalid_report_type(user_agent, document_url, blocked_url, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, sample, status_code):
    with pytest.raises(csp_reports.InvalidReportType):
        invalid_report_type = "invalid-type"
        report = csp_reports.get_report(generate_report_to(invalid_report_type, user_agent, document_url, blocked_url, document_url, effective_directive, original_policy, referrer, disposition, source_file, column_number, line_number, sample, status_code))


if __name__ == "__main__":
    pytest.main([__file__, "-vvv", "--no-cov"])