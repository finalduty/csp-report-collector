#!/usr/bin/env python3
__version__ = "0.4.0"

import html
import json
import logging
import os
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote_plus, urlparse  # https://docs.python.org/3/library/urllib.parse.html

import dotenv
from flask import Flask, Response, abort, jsonify, make_response, request
from pymongo import MongoClient  # https://www.mongodb.com/docs/drivers/pymongo/
from pymongo.database import Database
from pymongo.server_api import ServerApi

dotenv.load_dotenv()
logging.basicConfig(
    format='%(asctime)s [%(levelname)s]: %(name)s:%(lineno)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=os.environ.get('LOG_LEVEL', 'INFO'),
)

app = Flask(__name__)
log = logging.getLogger(__name__)

## Load config options from environment variables
API_BASE = os.environ.get('API_BASE', '/')

# MONGO_CONNECTION_STRING = "mongodb://{}:{}".format(OPTIONS["mongodb"]["host"], OPTIONS["mongodb"]["port"])
# CLIENT = MongoClient(MONGO_CONNECTION_STRING, username=OPTIONS["mongodb"]["user"], password=OPTIONS["mongodb"]["pass"])
# DB = CLIENT[OPTIONS["mongodb"]["database"]]


def connect_to_mongodb() -> Database:
    MONGO_DATABASE = os.environ.get("MONGO_DATABASE", "csp_reports")
    MONGO_USERNAME = quote_plus(os.environ.get('MONGO_USERNAME', ""))
    MONGO_PASSWORD = quote_plus(os.environ.get("MONGO_PASSWORD", ""))
    MONGO_PORT = os.environ.get('MONGO_PORT', 27017)

    if 'MONGO_CONNECTION_STRING' in os.environ:
        MONGO_CONNECTION_STRING = os.environ['MONGO_CONNECTION_STRING']
    elif 'MONGO_HOST' in os.environ:
        MONGO_HOST = os.environ['MONGO_HOST']
        MONGO_CONNECTION_STRING = f"mongodb://{MONGO_HOST}:{MONGO_PORT}"
    else:
        raise KeyError('Neither "MONGO_CONNECTION_STRING" or "MONGO_HOST" were defined')

    mongo_client = MongoClient(
        MONGO_CONNECTION_STRING,
        port=MONGO_PORT,
        username=MONGO_USERNAME,
        password=MONGO_PASSWORD,
        server_api=ServerApi('1'),
        tz_aware=True,
    )
    log.debug(f'Mongo Client: {mongo_client}')

    try:
        server_info = mongo_client.server_info()
        log.info(f"Connected to MongoDB {server_info['version']}")
        mongodb = mongo_client[MONGO_DATABASE]
    except Exception as e:
        log.error(f"Unable to connect to Mongo: {e}")
        mongodb = None

    return mongodb[MONGO_DATABASE]


@app.errorhandler(400)  # 400 Bad Request
def error_400(error):
    log.error(error)
    return make_response(jsonify({'error': str(error)}), 400)


@app.errorhandler(404)  # 404 Not Found
def error_404(error):
    return make_response(jsonify({'error': str(error)}), 404)


@app.errorhandler(405)  # 405 Method Not Allowed
def error_405(error):
    return make_response(jsonify({'error': str(error)}), 405)


@app.errorhandler(500)  # 500 Internal Server Error
def error_500(error):
    return make_response(jsonify({'error': str(error)}), 500)


@app.route(API_BASE, methods=["POST"])
def report_collector(mongo_database: Optional[Database] = None) -> Response:
    if not mongo_database:
        mongo_database = connect_to_mongodb()

    ## https://junxiandoc.readthedocs.io/en/latest/docs/flask/flask_request_response.html
    if request.content_type != "application/csp-report":
        abort(400)

    csp_report = json.loads(request.data.decode('UTF-8'))['csp-report']
    logging.info(f'{request.remote_addr} {request.content_type} {csp_report}')

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

    if mongo_database is not None:
        domain = urlparse(document_uri).hostname
        collection = mongo_database.get_collection(domain)
        data = {"blocked_uri": blocked_uri, "violated_directive": violated_directive}

        document = collection.find_one(data)

        if document:
            document_id = document['_id']
        else:
            document_id = collection.insert_one(data).inserted_id

        collection.update_one(
            {
                '_id': document_id,
            },
            {
                "$set": {'last_updated': datetime.now(timezone.utc)},
                '$inc': {'count': 1},
            },
        )
        return make_response(jsonify({}), 204)


@app.route(f'{API_BASE}/health')
def health():
    return make_response("ok", 200)


if __name__ == "__main__":
    ## Run local development instance. Start via gunicorn for a production instance.
    app.run(host="127.0.0.1", port=5000, debug=True)
