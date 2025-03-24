from datetime import datetime
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import URL, Enum
from typing import Literal
from typing import get_args


ReportDisposition = Literal["enforce", "report"]


class BaseModel(DeclarativeBase):
    __abstract__ = True  # So SQLAlchemy doesn't create this as a table
    pass


class ReportsModel(BaseModel):
    __tablename__ = "reports"

    """
    csp report can be in one of two forms:
    - The legacy `report-uri` format which is simplified json
        - Content-Type: application/csp-report
        - CSP 'report-uri' directive
    {
        "csp-report":
        {
            "blocked-uri": "The URI of the resource that was blocked from loading by the Content Security Policy.",
            "disposition": 'Either "enforce" or "report" depending on whether the Content-Security-Policy-Report-Only header or the Content-Security-Policy header is used',
            "document-uri": "The URI of the document in which the violation occurred."
            "effective-directive": "The directive whose enforcement caused the violation. eg 'style-src'".
            "original-policy": "The CSP policy from the header".
            "referrer": "The referrer of the document in which the violation occurred".
            "script-sample": "The first 40 characters of the inline script, event handler, or style that caused the violation.  Only relevant when 'report-sample' is used in policy".
            "status-code": "The HTTP status code of the resource on which the global object was instantiated.",
            "violated-directive": "The directive whose enforcement caused the violation. The violated-directive is a historic name for the effective-directive field and contains the same value."
        }
    }

    - The more complex CSPViolationReportBody that is a subcomponent of the Reporting API
        - Content-Type: application/reports+json
        - CSP 'report-to' directive
    {
        "age": 53531,
        "body": {
            "blockedURL": "inline",
            "columnNumber": 39,
            "disposition": "enforce",
            "documentURL": "https://example.com/violating/page",
            "effectiveDirective": "script-src-elem",
            "lineNumber": 121,
            "originalPolicy": "default-src 'self'; report-to csp-endpoint-name",
            "referrer": "https://www.examplesearchengine.com/",
            "sample": "console.log(\"lo\")",
            "sourceFile": "https://example.com/csp-report",
            "statusCode": 200
        },
        "type": "csp-violation",
        "url": "https://example.com/csp-report",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"
    }
    """

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(nullable=False, index=True)
    document_uri: Mapped[str] = mapped_column(nullable=False, index=True)
    blocked_uri: Mapped[str] = mapped_column(nullable=True, index=True)
    effective_directive: Mapped[str] = mapped_column(nullable=False, index=True)
    status_code: Mapped[int] = mapped_column(nullable=False)
    disposition: Mapped[ReportDisposition] = mapped_column(Enum(*get_args(ReportDisposition), name="disposition", create_constraint=True, validate_strings=True), nullable=False)
    original_policy: Mapped[str] = mapped_column(nullable=False)
    line_number: Mapped[int] = mapped_column(nullable=True)
    column_number: Mapped[int] = mapped_column(nullable=True)
    sample: Mapped[str] = mapped_column(nullable=True)
    referrer: Mapped[str] = mapped_column(nullable=True)
    user_agent: Mapped[str] = mapped_column(nullable=True)
    reported_at: Mapped[datetime] = mapped_column(nullable=False)
