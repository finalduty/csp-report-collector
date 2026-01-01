#!/usr/bin/env python3
import html
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

import dotenv
from flask import Blueprint, Flask, abort, current_app, jsonify, make_response, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

__version__ = "0.4.2"

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
routes = Blueprint("routes", __name__)


class BaseModel(DeclarativeBase):
    __abstract__ = True  # So SQLAlchemy doesn't create this as a table


class ReportsModel(BaseModel):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(primary_key=True)
    domain: Mapped[str] = mapped_column(nullable=False, index=True)
    document_uri: Mapped[str] = mapped_column(nullable=False, index=True)
    blocked_uri: Mapped[str] = mapped_column(nullable=False, index=True)
    violated_directive: Mapped[str] = mapped_column(nullable=False, index=True)
    reported_at: Mapped[datetime] = mapped_column(nullable=False)


### Private Functions ###
def _load_config(config_path: Optional[str] = "settings.conf", env_prefix: str = "CSPRC") -> dict:
    ## Initialise supported variables
    config: dict = {
        "db_uri": None,
        "db_type": None,
        "db_host": None,
        "db_port": None,
        "db_username": None,
        "db_password": None,
        "db_name": None,
    }
    output = {}

    if config_path:
        _load_config_from_file(config, config_path)
    _load_config_from_environment(config, env_prefix)

    ## If a DB URI is provided, combine any individually provided components
    if config["db_uri"]:
        from sqlalchemy import make_url

        db_uri = make_url(config["db_uri"])
        db_uri.set(
            drivername=config["db_type"] if config["db_type"] else db_uri.drivername,
            username=config["db_username"] if config["db_username"] else db_uri.username,
            password=config["db_password"] if config["db_password"] else db_uri.password,
            host=config["db_host"] if config["db_host"] else db_uri.host,
            port=int(config["db_port"]) if config["db_port"] else db_uri.port,
            database=config["db_name"] if config["db_name"] else db_uri.database,
        )

        output["SQLALCHEMY_DATABASE_URI"] = str(db_uri)

    return output


def _load_config_from_file(config: dict, config_path: str):
    if config_path and os.path.isfile(config_path):
        from configparser import ConfigParser

        parser = ConfigParser()
        parser.read(config_path)

        for key in config.keys():
            if parser.has_option("main", key):
                config.update({key: parser["main"][key]})


def _load_config_from_environment(config: dict, env_prefix: str):
    for key in config.keys():
        envvar = f"{env_prefix}_{key}".upper()

        if envvar in os.environ:
            config.update({key: os.environ[envvar]})


def _write_to_database(
    db: SQLAlchemy,
    domain: str,
    blocked_uri: str,
    document_uri: str,
    reported_at: datetime,
    violated_directive: str,
) -> None:
    """
    Inserts a new CSP report entry into the database.

    Args:
        db (SQLAlchemy): The SQLAlchemy database instance.
        domain (str): The domain where the CSP violation occurred.
        blocked_uri (str): The URI that was blocked by the CSP.
        document_uri (str): The URI of the document in which the violation occurred.
        reported_at (datetime): The timestamp when the violation was reported.
        violated_directive (str): The CSP directive that was violated.

    Returns:
        None
    """
    report = ReportsModel(
        domain=domain,
        document_uri=document_uri,
        blocked_uri=blocked_uri,
        violated_directive=violated_directive,
        reported_at=reported_at,
    )
    db.session.add(report)
    db.session.commit()


### Application Factory ###
def create_app(override: Optional[dict] = None) -> Flask:
    """
    Flask application factory. Allows passing a test_config dict for overrides.
    """
    app = Flask(__name__, instance_path=os.path.abspath(os.path.expanduser("tmp/")))
    config = _load_config()

    if override:
        config.update(override)

    app.config.update(config)

    # Set up DB connection if configured
    if app.config.get("SQLALCHEMY_DATABASE_URI"):
        db = SQLAlchemy(model_class=BaseModel)
        db.init_app(app)

        with app.app_context():
            db.create_all()

        app.config["db"] = db
    else:
        app.config["db"] = None

    @app.errorhandler(400)  # 400 Bad Request
    def error_400(error):
        return make_response(jsonify({"error": str(error)}), 400)

    @app.errorhandler(404)  # 404 Not Found
    def error_404(error):
        return make_response(jsonify({"error": str(error)}), 404)

    @app.errorhandler(405)  # 405 Method Not Allowed
    def error_405(error):
        return make_response(jsonify({"error": str(error)}), 405)

    app.register_blueprint(routes)

    return app


### Routes ###
@routes.route("/", methods=["POST"])
def csp_receiver():
    if request.content_type != "application/csp-report":
        abort(400, f"Invalid content type. Expected 'application/csp-report', got '{request.content_type}'.")

    csp_report = json.loads(request.data.decode("UTF-8"))["csp-report"]
    log.info(f"{datetime.now(timezone.utc)} {request.remote_addr} {request.content_type} {csp_report}")

    try:
        blocked_uri = html.escape(csp_report["blocked-uri"], quote=True).split(" ", 1)[0]
    except AttributeError:
        blocked_uri = None

    document_uri = html.escape(csp_report["document-uri"], quote=True).split(" ", 1)[0]
    violated_directive = html.escape(csp_report["violated-directive"], quote=True).split(" ", 1)[0]

    domain = urlparse(document_uri).hostname

    if blocked_uri == "about" or document_uri == "about":
        return make_response(jsonify({}), 204)
    elif not blocked_uri:
        if violated_directive == "script-src":
            blocked_uri = "eval"
        elif violated_directive == "style-src":
            blocked_uri = "inline"

    if current_app.config["db"]:
        _write_to_database(
            db=current_app.config["db"],
            reported_at=datetime.now(timezone.utc),
            domain=domain,
            document_uri=document_uri,
            blocked_uri=str(blocked_uri),
            violated_directive=violated_directive,
        )

    return make_response(jsonify({}), 204)


@routes.route("/status")
def status():
    return make_response("ok", 200)


if __name__ == "__main__":  # pragma: nocover
    app = create_app()
    app.run(host="127.0.0.1")
