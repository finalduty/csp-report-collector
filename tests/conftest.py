import csp_datamodel
import pytest

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

class FixedData(object):
    @staticmethod
    def none() -> None:
        return None
    
    @staticmethod
    def empty() -> str:
        return ""
    
    @staticmethod
    def content_type(type) -> str:
        content_types = {
            "invalid": "text/html",
            "legacy": "application/csp-report",
            "preferred": "application/reports+json"
        }

        try:
            return content_types[type]
        except KeyError:
            return content_types["legacy"]
        
    @staticmethod
    def report_type(type) -> str:    
        report_types = {
            "legacy": "csp-report",
            "preferred": "csp-violation",
            "invalid": "invalid-report",
            "missing": ""
        }

        try:
            return report_types[type]
        except KeyError:
            return ""
        
    @staticmethod
    def request_uri(type) -> str:
        uris = {
            "submit": "/csp-report",
            "list": "/reports",
            "detail": "/reports/1",
            "invalid": "/invalid",
        }

        try:
            return uris[type]
        except KeyError:
            return ""
        
    @staticmethod
    def user_agent() -> str:
        return "Mozilla/5.0 - pytest"
    
    @staticmethod
    def document_url() -> str:
        return "https://pytest.test-domain.com/test"

    @staticmethod
    def blocked_url() -> str:
        return "https://www.evil.com/payload/evil.js"

    @staticmethod
    def effective_directive() -> str:
        return "inline-src"
    
    @staticmethod
    def original_policy() -> str:
        return "default-src 'self';"

    @staticmethod
    def referrer() -> str:
        return "https://www.duckduckgo.com"

    @staticmethod
    def source_file() -> str:
        return "https://my-domain.com/about"

    @staticmethod
    def disposition() -> str:
        return "enforce"

    @staticmethod
    def column_number() -> str:
        return "39"

    @staticmethod
    def line_number() -> str:
        return "17"

    @staticmethod
    def code_sample() -> str:
        return "<javascript>alert(1);</javascript>"

    @staticmethod
    def status_code() -> str:
        return "200"

@pytest.fixture(scope="function")
def get_db():
    engine = create_engine("sqlite:///:memory:")
    csp_datamodel.ReportsModel.metadata.create_all(engine)
    Session = sessionmaker(bind=engine,expire_on_commit=False)
    with Session() as db:
        yield db