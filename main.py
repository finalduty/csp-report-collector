#!/usr/bin/env python3
__version__ = "0.3.0"

# Standard library imports
from urllib.parse import urlparse
from datetime import datetime
import html
import json
import logging
import os

# Third party library imports
from configparser import ConfigParser, NoOptionError
from flask import Flask, jsonify, abort, make_response, request
from pymongo import MongoClient

# Debug
# from pdb import set_trace as st

app = Flask(__name__)

if "REPORT_API_PATH" in os.environ:
    REPORT_API_PATH = os.environ["REPORT_API_PATH"]
else:
    REPORT_API_PATH = "/"


def read_conf(conf_path):
    """
    Read CASSH configuration file and return metadata.
    """

    if not os.path.isfile(conf_path):
        LOG.error("Can't read configuration file... ({})".format(conf_path))
        exit(1)

    config = ConfigParser()
    config.read(conf_path)
    options = dict()

    options["mongodb"] = dict()
    if not config.has_option("mongodb", "enable"):
        options["mongodb"]["enable"] = False
    else:
        options["mongodb"]["enable"] = config.get("mongodb", "enable") == "True"
    try:
        options["mongodb"]["port"] = int(config.get("mongodb", "port"))
        options["mongodb"]["host"] = config.get("mongodb", "host")
        options["mongodb"]["user"] = config.get("mongodb", "user")
        if options["mongodb"]["user"] == "None":
            options["mongodb"]["user"] = None
        options["mongodb"]["pass"] = config.get("mongodb", "pass")
        if options["mongodb"]["pass"] == "None":
            options["mongodb"]["pass"] = None
        options["mongodb"]["database"] = config.get("mongodb", "database")
    except (NoOptionError, ValueError) as error_msg:
        LOG.error("Can't read configuration file... ({})".format(error_msg))
        exit(1)

    return options


@app.errorhandler(400)  # 400 Bad Request
def error_400(error):
    return make_response(jsonify({
        'error': str(error)
    }), 400)


@app.errorhandler(404)  # 404 Not Found
def error_404(error):
    return make_response(jsonify({
        'error': str(error)
    }), 404)


@app.errorhandler(405)  # 405 Method Not Allowed
def error_405(error):
    return make_response(jsonify({
        'error': str(error),
    }), 405)


@app.route(REPORT_API_PATH, methods=['POST'])
def csp_receiver():
    ## https://junxiandoc.readthedocs.io/en/latest/docs/flask/flask_request_response.html
    if request.content_type != "application/csp-report":
        abort(400)

    csp_report = json.loads(request.data.decode('UTF-8'))['csp-report']
    logging.info(f'{datetime.now()} {request.remote_addr} {request.content_type} {csp_report}')

    blocked_uri = html.escape(csp_report['blocked-uri'], quote=True).split(' ', 1)[0]
    document_uri = html.escape(csp_report['document-uri'], quote=True).split(' ', 1)[0]
    violated_directive = html.escape(csp_report['violated-directive'], quote=True).split(' ', 1)[0]

    if blocked_uri == 'about' or document_uri == 'about':
        return make_response('', 204)

    elif not blocked_uri:
        if violated_directive == 'script-src':
            blocked_uri = 'eval'

        elif violated_directive == 'style-src':
            blocked_uri = 'inline'

    if OPTIONS["mongodb"]["enable"]:
        domain = urlparse(document_uri).hostname
        collection = DB[domain]
        post = {"blocked_uri": blocked_uri, "violated_directive": violated_directive}

        document = collection.find_one(post)

        if document:
            document_id = document['_id']
        else:
            document_id = collection.insert_one(post).inserted_id

        collection.update_one({'_id': document_id}, {"$set": {'last_updated': datetime.now()}, '$inc': {'count': 1}})

    return make_response('', 204)


@app.route("/health")
def health():
    result = {"name": "csp-report", "version": __version__}
    return make_response(json.dumps(result), 200)


LOG = logging.getLogger("werkzeug")
OPTIONS = read_conf("settings.conf")
MONGO_CONNECTION_STRING = "mongodb://{}:{}".format(OPTIONS["mongodb"]["host"], OPTIONS["mongodb"]["port"])
CLIENT = MongoClient(MONGO_CONNECTION_STRING, username=OPTIONS["mongodb"]["user"], password=OPTIONS["mongodb"]["pass"])
DB = CLIENT[OPTIONS["mongodb"]["database"]]


if __name__ == "__main__":
    app.run(host="0.0.0.0")
