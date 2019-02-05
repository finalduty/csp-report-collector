#!/usr/bin/env python3

from flask import Flask, jsonify, abort, make_response, request
from pymongo import MongoClient
from urllib.parse import urlparse
import datetime
import html
import os

mongo_host = (os.getenv('CSP_MONGO_HOST', 'localhost'))
mongo_port = (os.getenv('CSP_MONGO_PORT', 27017))
mongo_user = (os.getenv('CSP_MONGO_USER', None))
mongo_pass = (os.getenv('CSP_MONGO_PASS', None))
mongo_database = (os.getenv('CSP_MONGO_DATABASE', 'csp_reports'))
mongo_connection_string = (os.getenv('CSP_MONGO_CONNECTION_STRING', "mongodb://" + str(mongo_host) + ":" + str(mongo_port)))


app = Flask(__name__)
client = MongoClient(mongo_connection_string, username=mongo_user, password=mongo_pass)
db = client[mongo_database]


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


@app.route('/', methods=['POST'])
def csp_receiver():
    if not request.json:
        abort(400)

    csp_report = request.json['csp-report']
    document_uri = html.escape(csp_report['document-uri'], quote=True)
    blocked_uri = html.escape(csp_report['blocked-uri'], quote=True)
    violated_directive = html.escape(csp_report['violated-directive'], quote=True)
    disposition = html.escape(csp_report['disposition'], quote=True)

    domain = urlparse(document_uri).hostname
    collection = db[domain]

    post = {"disposition": disposition, "blocked_uri": blocked_uri, "violated_directive": violated_directive}
    document = collection.find_one(post)

    if document:
        document_id = document['_id']
    else:
        document_id = collection.insert_one(post).inserted_id

    collection.update_one({'_id': document_id}, {"$set": {'last_updated': datetime.datetime.now()}, '$inc': {'count': 1}})

    return make_response('', 204)


if __name__ == "__main__":
    app.run(host="0.0.0.0")
