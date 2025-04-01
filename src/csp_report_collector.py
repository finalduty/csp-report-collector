#!/usr/bin/env python3
import json
import logging
import os
import csp_reports, csp_datamodel
from datetime import datetime
from typing import Optional

import dotenv
from flask import Flask, abort, jsonify, make_response, request, render_template, Response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import URL

__version__ = "1.0.0"

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
    level=logging.INFO,
)

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

    app.config["SQLALCHEMY_DATABASE_URI"] = URL.create(
        drivername=app.config["db_type"],
        username=app.config["db_username"],
        password=app.config["db_password"],
        host=app.config["db_host"],
        port=app.config["db_port"],
        database=app.config["db_name"],
    )

    db = SQLAlchemy(model_class=csp_datamodel.BaseModel)
    db.init_app(app)

    with app.app_context():
        db.create_all()

app.config["db"] = db

### Flask Handlers ###


@app.errorhandler(400)  # 400 Bad Request
def error_400(error):
    app.logger.warning(f"Error[400]: {error}")
    return make_response(jsonify({"error": str(error)}), 400)


@app.errorhandler(404)  # 404 Not Found
def error_404(error):
    return make_response(jsonify({"error": str(error)}), 404)


@app.errorhandler(405)  # 405 Method Not Allowed
def error_405(error):
    return make_response(jsonify({"error": str(error)}), 405)


@app.errorhandler(500)  # 500 Internal Server Error
def error_500(error):
    app.logger.error(f"Error[500]: {error}")
    return make_response(jsonify({"error": "Unable to handle request.  See logs for details."}))


@app.route("/csp-report", methods=["POST"])
def csp_receiver():
    ## https://junxiandoc.readthedocs.io/en/latest/docs/flask/flask_request_response.html

    report_json = request.get_json(force=True)
    app.logger.debug(f"{datetime.now()} {request.remote_addr} {request.content_type} {report_json}")

    if not request.content_type in csp_reports.csp_content_type:
        abort(400, f"Invalid content type. Expected one of {" ".join(csp_reports.csp_content_type)}, got '{request.content_type}'.")

        csp_report: csp_reports.CSPReport
    try:
        csp_report = csp_reports.get_report(report_json)
    except csp_reports.RequiredElementMissingError as err:
        app.logger.warning(f"Unable to parse report ({err.__class__.__name__}): {err}")
        abort(400, err)
    except csp_reports.AboutException:
        return make_response(jsonify({}), 204)

    try:
        if app.config["db"]:
            csp_report.write(db.session)
    except Exception as e:
        abort(500, e)

    return make_response(jsonify({}), 204)


@app.route("/reports", methods=["GET"])
def display_csp_reports():
    pagenum: int = int(request.args.get("p", 1))
    pagesize: int = 50
    db: SQLAlchemy = app.config["db"]
    reports = db.paginate(db.select(csp_datamodel.ReportsModel).order_by(csp_datamodel.ReportsModel.reported_at), page=pagenum, per_page=pagesize, max_per_page=100)
    return render_template("reports.jinja", reports=reports)


@app.route("/reports/<int:id>", methods=["GET"])
def display_single_report(id: int):
    db: SQLAlchemy = app.config["db"]
    report = db.session.execute(db.select(csp_datamodel.ReportsModel).filter_by(id=id)).scalar_one()
    return render_template("reports_detail.jinja", report=report)


@app.route("/status")
def status():
    return make_response("ok", 200)


if __name__ == "__main__":  # pragma: nocover
    app.run(host="127.0.0.1")
