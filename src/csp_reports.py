import abc
import html

from csp_datamodel import ReportsModel

from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm.session import Session
from urllib.parse import urlparse


class AboutException(Exception):
    pass

class RequiredElementMissingError(Exception):
    pass

class InvalidReportType(RequiredElementMissingError):
    pass

class CSPReport(abc.ABC):
    def __init__(self,received: datetime):
        self.received = received

    @abc.abstractmethod
    def write(self, db: SQLAlchemy):
        pass

# See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-uri#violation_report_syntax
# Officially deprecated
class ReportURI(CSPReport):
    def __init__(self, request_data: dict, received: datetime = datetime.now(timezone.utc)):
        try:
            csp_report = request_data["csp-report"]
        except KeyError:
            raise InvalidReportType("Report is not of the 'csp-report' type")
        
        super().__init__(received)

        try:
            self.blocked_uri = html.escape(csp_report["blocked-uri"], quote=True).split(" ", 1)[0]
        except KeyError:
            self.blocked_uri = None

        try:
            self.document_uri = html.escape(csp_report["document-uri"], quote=True).split(" ", 1)[0]
        except KeyError:
            raise RequiredElementMissingError("Missing required element 'document-uri'")
        
        try:
            self.effective_directive = html.escape(csp_report["effective-directive"], quote=True).split(" ", 1)[0]
        except KeyError:
            try:
                self.effective_directive = html.escape(csp_report["violated-directive"], quote=True).split(" ", 1)[0]
            except KeyError:
                raise RequiredElementMissingError("Missing required element.  Either 'violated-directive' (deprecated) or 'effective-directive' is required.")

        try:
            self.sample = html.escape(csp_report["script-sample"], quote=True)
        except KeyError:
            self.sample = None

        try:
            self.referrer = html.escape(csp_report["referrer"], quote=True)
        except KeyError:
            self.referrer = None

        self.domain = urlparse(self.document_uri).hostname

        ## Short-ciruit reports for 'about' pages, i.e. about:config, etc.
        if self.blocked_uri == "about" or self.document_uri == "about":
            raise AboutException()

        elif not self.blocked_uri:
            if self.effective_directive == "script-src":
                self.blocked_uri = "eval"

        elif self.effective_directive == "style-src":
            self.blocked_uri = "inline"

        try:
            self.disposition = html.escape(csp_report["disposition"])
            self.status_code = int(csp_report["status-code"])
            self.original_policy = html.escape(csp_report["original-policy"])
        except KeyError as e:
            raise RequiredElementMissingError(f"Missing required element: {e}")

    def write(self, db_session: Session) -> None:
        report = ReportsModel(
            domain=self.domain,
            document_uri=self.document_uri,
            blocked_uri=self.blocked_uri,
            effective_directive=self.effective_directive,
            status_code=self.status_code,
            disposition=self.disposition,
            sample=self.sample,
            original_policy=self.original_policy,
            referrer=self.referrer,
            reported_at=self.received
        )

        db_session.add(report)
        db_session.commit()

# See https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to
# See also https://www.w3.org/TR/CSP3/#reporting
class ReportTo(CSPReport):
    def __init__(self, request_data: dict, received: datetime = datetime.now(timezone.utc)):
        super().__init__(received)

        self._violation_uri_types = [
            "inline", "eval", "wasm-eval", "trusted-types-policy", "trusted-types-sink"
        ]

        try:
            if request_data["type"] != "csp-violation":
                raise InvalidReportType(f"Report type must be 'csp-violation' but got {request_data["type"]}")
        except KeyError:
            raise InvalidReportType(f"Report is not a valid csp-violation report: missing 'type': 'csp-violation'")
        
        try:
            self.user_agent = html.escape(request_data["user_agent"], quote=True)
        except KeyError:
            self.user_agent = None
        
        csp_report = {}

        try:
            csp_report: dict = request_data["body"]
            self.document_uri = html.escape(csp_report["documentURL"], quote=True).split(" ", 1)[0]
            self.domain = urlparse(self.document_uri).hostname
            self.effective_directive = html.escape(csp_report["effectiveDirective"], quote=True).split(" ", 1)[0]
            self.disposition = html.escape(csp_report["disposition"], quote=True)
            self.status_code = int(csp_report["statusCode"])
            self.original_policy = html.escape(csp_report["originalPolicy"], quote=True)
            self.sample = html.escape(csp_report["sample"],quote=True)
        except KeyError as e:
            raise RequiredElementMissingError("Missing required element '{e}'")
        
        try:
            self.blocked_uri = html.escape(csp_report["blockedURL"], quote=True).split(" ", 1)[0]
        except KeyError:
            self.blocked_uri = None

        ## Short-ciruit reports for 'about' pages, i.e. about:config, etc.
        if self.blocked_uri == "about" or self.document_uri == "about":
            raise AboutException()
        
        # blockedURL must be one of a set of strings, or a valid URL
        if self.blocked_uri not in self._violation_uri_types and self.blocked_uri is not None:
            parsed_blocked_uri = urlparse(self.blocked_uri)
            if parsed_blocked_uri.scheme not in ["http", "https", "ws", "wss"] or not parsed_blocked_uri.netloc:
                raise RequiredElementMissingError("BlockedURI is not a valid string or URL")
        
        try:
            self.column_number = int(csp_report["columnNumber"])
        except KeyError:
            self.column_number = None

        try:
            self.line_number = int(csp_report["lineNumber"])
        except KeyError:
            self.line_number = None

        try:
            self.referrer = html.escape(csp_report["referrer"])
        except KeyError:
            self.referrer = None

    def write(self, db_session: Session) -> None:
        report = ReportsModel(
            domain=self.domain,
            document_uri=self.document_uri,
            blocked_uri=self.blocked_uri,
            effective_directive=self.effective_directive,
            status_code=self.status_code,
            disposition=self.disposition,
            original_policy=self.original_policy,
            line_number=self.line_number,
            column_number=self.column_number,
            sample=self.sample,
            referrer=self.referrer,
            user_agent=self.user_agent,
            reported_at=self.received
        )

        db_session.add(report)
        db_session.commit()

def get_report(report: dict) -> CSPReport:
    try:
        return ReportTo(report)
    except InvalidReportType:
        try:
            return ReportURI(report)
        except InvalidReportType:
            raise InvalidReportType("Submitted report could not be serialized: unknown or invalid report type")

csp_content_type = [
    "application/csp-report", 
    "application/reports+json"
]