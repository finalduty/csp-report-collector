#!/usr/bin/env python3
import html
import json
import logging
import os
from datetime import datetime
from typing import Optional
from urllib.parse import urlparse

import dotenv
from flask import Flask, abort, jsonify, make_response, request

__version__ = "0.4.0"

SUPPORTED_DB_ENGINES = [
    "mariadb",
    "mssql",
    "mysql",
    "postgresql",
    "sqlite",
]

dotenv.load_dotenv()
logging.basicConfig(
    format="%(asctime)s [%(levelname)s]: %(name)s:%(lineno)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

log = logging.getLogger("werkzeug")


### Private Functions ###


def _load_config(config_path: Optional[str] = "settings.conf", env_prefix: str = "CSPRC") -> dict:
    ## Initialise supported variables
    config: dict[str, Optional[str]] = {
        "db_uri": None,
        "db_type": None,
        "db_host": None,
        "db_port": None,
        "db_username": None,
        "db_password": None,
        "db_name": None,
    }

    ## Load config from file
    if config_path and os.path.isfile(config_path):
        from configparser import ConfigParser

        parser = ConfigParser()
        parser.read(config_path)

        for key in config.keys():
            if parser.has_option("main", key):
                config.update({key: parser["main"][key]})

    ## Load config from environment
    for key in config.keys():
        envvar = f"{env_prefix}_{key}".upper()

        if envvar in os.environ:
            config.update({key: os.environ[envvar]})

    ## If a DB URI is provided, extract it's components and store them
    if config["db_uri"]:
        from sqlalchemy import make_url

        db_uri = make_url(config["db_uri"])

        config["db_type"] = db_uri.drivername if db_uri.drivername else config["db_type"]
        config["db_host"] = db_uri.host if db_uri.drivername else config["db_host"]
        config["db_port"] = str(db_uri.port) if db_uri.port else config["db_port"]
        config["db_username"] = db_uri.username if db_uri.username else config["db_username"]
        config["db_password"] = db_uri.password if db_uri.password else config["db_password"]
        config["db_name"] = db_uri.database if db_uri.database else config["db_name"]

    return config


## Initialise Flask App
app = Flask(__name__, instance_path=os.path.abspath(os.path.expanduser("tmp/")))
app.config.update(_load_config())

## Set up DB connections
db = None

if app.config["db_type"]:
    from flask_sqlalchemy import SQLAlchemy
    from sqlalchemy import URL
    from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

    class BaseModel(DeclarativeBase):
        __abstract__ = True  # So SQLAlchemy doesn't create this as a table
        pass

    class ReportsModel(BaseModel):
        __tablename__ = "reports"

        id: Mapped[int] = mapped_column(primary_key=True)
        domain: Mapped[str] = mapped_column(nullable=False, index=True)
        document_uri: Mapped[str] = mapped_column(nullable=False, index=True)
        blocked_uri: Mapped[str] = mapped_column(nullable=False, index=True)
        violated_directive: Mapped[str] = mapped_column(nullable=False, index=True)
        reported_at: Mapped[datetime] = mapped_column(nullable=False)

    app.config["SQLALCHEMY_DATABASE_URI"] = URL.create(
        drivername=app.config["db_type"],
        username=app.config["db_username"],
        password=app.config["db_password"],
        host=app.config["db_host"],
        port=app.config["db_port"],
        database=app.config["db_name"],
    )

    db = SQLAlchemy(model_class=BaseModel)
    db.init_app(app)

    with app.app_context():
        db.create_all()

app.config["db"] = db

### Flask Handlers ###


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
        abort(400, f"Invalid content type. Expected 'application/csp-report', got '{request.content_type}'.")

    csp_report = json.loads(request.data.decode("UTF-8"))["csp-report"]
    log.info(f"{datetime.now()} {request.remote_addr} {request.content_type} {csp_report}")

    try:
        blocked_uri = html.escape(csp_report["blocked-uri"], quote=True).split(" ", 1)[0]
    except AttributeError:
        blocked_uri = None

    document_uri = html.escape(csp_report["document-uri"], quote=True).split(" ", 1)[0]
    violated_directive = html.escape(csp_report["violated-directive"], quote=True).split(" ", 1)[0]

    domain = urlparse(document_uri).hostname

    ## Short-ciruit reports for 'about' pages, i.e. about:config, etc.
    if blocked_uri == "about" or document_uri == "about":
        return make_response(jsonify({}), 204)

    elif not blocked_uri:
        if violated_directive == "script-src":
            blocked_uri = "eval"

        elif violated_directive == "style-src":
            blocked_uri = "inline"

    if app.config["db"]:
        _write_to_database(
            db=app.config["db"],
            reported_at=datetime.utcnow(),
            domain=domain,
            document_uri=document_uri,
            blocked_uri=str(blocked_uri),
            violated_directive=violated_directive,
        )

    return make_response(jsonify({}), 204)


def _write_to_database(
    db: SQLAlchemy,
    domain: str,
    blocked_uri: str,
    document_uri: str,
    reported_at: datetime,
    violated_directive: str,
) -> None:
    report = ReportsModel(
        domain=domain,
        document_uri=document_uri,
        blocked_uri=blocked_uri,
        violated_directive=violated_directive,
        reported_at=reported_at,
    )

    db.session.add(report)
    db.session.commit()


@app.route("/status")
def status():
    return make_response("ok", 200)


if __name__ == "__main__":  # pragma: nocover
    app.run(host="127.0.0.1")
