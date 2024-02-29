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
from sqlalchemy.dialects import __all__ as SQLALCHEMY_DIALECTS

__version__ = "0.4.0"

SUPPORTED_DB_ENGINES = [
    "mariadb",
    "mongodb",
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
        "db_engine": None,
        "db_host": None,
        "db_port": None,
        "db_username": None,
        "db_password": None,
        "db_path": None,
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

    ## If a DB URI is provided, extract and store it's engine as well
    if config["db_uri"]:
        config["db_engine"] = config["db_uri"].split("://")[0]

    return config


## Initialise Flask App
app = Flask(__name__, instance_path=os.path.abspath(os.path.expanduser("tmp/")))
app.config.update(_load_config())

## Set up DB connections
db = None

if app.config["db_engine"]:
    if app.config["db_engine"] == "mongodb":
        from pymongo import MongoClient

        mongo_client = MongoClient(
            host=app.config["db_uri"] if app.config["db_uri"] is not None else app.config["db_host"],
            port=int(app.config["db_port"]),
            username=app.config["db_username"],
            password=app.config["db_password"],
        )

        db = mongo_client[app.config["db_name"]]

    elif app.config["db_engine"] in SQLALCHEMY_DIALECTS:
        from flask_sqlalchemy import SQLAlchemy
        from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

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

        if app.config["db_uri"]:
            app.config["SQLALCHEMY_DATABASE_URI"] = app.config["db_uri"]
        else:
            from sqlalchemy import URL

            app.config["SQLALCHEMY_DATABASE_URI"] = URL.create(
                drivername=app.config["db_engine"],
                username=app.config["db_username"],
                password=app.config["db_password"],
                host=app.config["db_host"],
                port=app.config["db_port"],
                database=app.config["db_name"],
            )

        db = SQLAlchemy(model_class=Base)
        db.init_app(app)

        with app.app_context():
            db.create_all()

    else:
        raise ValueError(f"Unsupported database engine '{app.config['db_engine']}'. Please choose one of the supported engines: {', '.join(SUPPORTED_DB_ENGINES)}")

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


def _write_to_storage(
    domain: str,
    document_uri: str,
    blocked_uri: str,
    violated_directive: str,
    reported_at: datetime,
) -> None:
    pass


def _write_to_sql(
    domain: str,
    document_uri: str,
    blocked_uri: str,
    violated_directive: str,
    reported_at: datetime,
) -> None:
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
