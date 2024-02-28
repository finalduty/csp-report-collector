#!/usr/bin/env python3
import html
import json
import logging
import os
from datetime import datetime
from urllib.parse import urlparse

import dotenv
from flask import Flask, abort, jsonify, make_response, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__version__ = "0.4.0"


dotenv.load_dotenv()
logging.basicConfig(
    format="%(asctime)s [%(levelname)s]: %(name)s:%(lineno)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


class Base(DeclarativeBase):
    __abstract__ = True  # So SQLAlchemy doesn't create this as a table
    pass


class Reports(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(nullable=False, index=True)
    document_uri: Mapped[str] = mapped_column(nullable=False, index=True)
    blocked_uri: Mapped[str] = mapped_column(nullable=False, index=True)
    violated_directive: Mapped[str] = mapped_column(nullable=False, index=True)
    reported_at: Mapped[datetime] = mapped_column(nullable=False)


log = logging.getLogger("werkzeug")


## Initialise Flask App
app = Flask(__name__, instance_path=os.path.abspath(os.path.expanduser("tmp/")))
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("CSPRC_DB_URI", "sqlite:///db.sqlite")

db = SQLAlchemy(model_class=Base)
db.init_app(app)

with app.app_context():
    db.create_all()


@app.errorhandler(400)  # 400 Bad Request
def error_400(error):
    return make_response(jsonify({"error": str(error)}), 400)


@app.errorhandler(404)  # 404 Not Found
def error_404(error):
    return make_response(jsonify({"error": str(error)}), 404)


@app.errorhandler(405)  # 405 Method Not Allowed
def error_405(error):
    return make_response(jsonify({"error": str(error)}), 405)


@app.route("/", methods=["POST"])
def csp_receiver():
    ## https://junxiandoc.readthedocs.io/en/latest/docs/flask/flask_request_response.html
    if request.content_type != "application/csp-report":
        abort(400)

    csp_report = json.loads(request.data.decode("UTF-8"))["csp-report"]
    log.info(f"{datetime.now()} {request.remote_addr} {request.content_type} {csp_report}")

    blocked_uri = html.escape(csp_report["blocked-uri"], quote=True).split(" ", 1)[0]
    document_uri = html.escape(csp_report["document-uri"], quote=True).split(" ", 1)[0]
    violated_directive = html.escape(csp_report["violated-directive"], quote=True).split(" ", 1)[0]

    domain = urlparse(document_uri).hostname

    if blocked_uri == "about" or document_uri == "about":
        return make_response("", 204)

    elif not blocked_uri:
        if violated_directive == "script-src":
            blocked_uri = "eval"

        elif violated_directive == "style-src":
            blocked_uri = "inline"

    _write_to_sql(
        reported_at=datetime.utcnow(),
        domain=domain,
        document_uri=document_uri,
        blocked_uri=blocked_uri,
        violated_directive=violated_directive,
    )

    return make_response("", 204)


def _write_to_sql(domain: str, document_uri: str, blocked_uri: str, violated_directive: str, reported_at: datetime) -> None:
    report = Reports(
        domain=domain,
        document_uri=document_uri,
        blocked_uri=blocked_uri,
        violated_directive=violated_directive,
        reported_at=reported_at,
    )

    db.session.add(report)
    db.session.commit()


@app.route("/health")
def health():
    result = {"name": "csp-report", "version": __version__}
    return make_response(json.dumps(result), 200)


if __name__ == "__main__":
    app.run(host="127.0.0.1")
