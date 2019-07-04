#!/usr/bin/env python3

from flask import Flask, jsonify, abort, make_response, request
from pymongo import MongoClient
from urllib.parse import urlparse
import datetime
import html
import os
import json
from ssl import PROTOCOL_TLSv1_2, SSLContext

mongo_host = (os.getenv('CSP_MONGO_HOST', 'localhost'))
mongo_port = (os.getenv('CSP_MONGO_PORT', 27017))
mongo_user = (os.getenv('CSP_MONGO_USER', None))
mongo_pass = (os.getenv('CSP_MONGO_PASS', None))
mongo_database = (os.getenv('CSP_MONGO_DATABASE', 'csp_reports'))
mongo_connection_string = (os.getenv('CSP_MONGO_CONNECTION_STRING', "mongodb://" + str(mongo_host) + ":" + str(mongo_port)))


APP = Flask(__name__)
client = MongoClient(mongo_connection_string, username=mongo_user, password=mongo_pass)
db = client[mongo_database]


@APP.errorhandler(400)  # 400 Bad Request
def error_400(error):
    return make_response(jsonify({
        'error': str(error)
    }), 400)


@APP.errorhandler(404)  # 404 Not Found
def error_404(error):
    return make_response(jsonify({
        'error': str(error)
    }), 404)


@APP.errorhandler(405)  # 405 Method Not Allowed
def error_405(error):
    return make_response(jsonify({
        'error': str(error),
    }), 405)


@APP.route('/', methods=['POST'])
def csp_receiver():
    ## https://junxiandoc.readthedocs.io/en/latest/docs/flask/flask_request_response.html
    if request.content_type != "application/csp-report":
        abort(400)

    csp_report = json.loads(request.data.decode("UTF-8"))['csp-report']
    print(datetime.datetime.now(), request.remote_addr, request.content_type, csp_report)

    blocked_uri = html.escape(csp_report['blocked-uri'], quote=True).split(' ', 1)[0]
    document_uri = html.escape(csp_report['document-uri'], quote=True).split(' ', 1)[0]
    violated_directive = html.escape(csp_report['violated-directive'], quote=True).split(' ', 1)[0]
    #disposition = html.escape(csp_report['disposition'], quote=True)

    if blocked_uri == 'about':
        return make_response('', 204)

    elif not blocked_uri:
        if violated_directive == 'script-src':
            blocked_uri = 'eval'

        elif violated_directive == 'style-src':
            blocked_uri = 'inline'

    domain = urlparse(document_uri).hostname
    collection = db[domain]
    post = {"blocked_uri": blocked_uri, "violated_directive": violated_directive}
    
    document = collection.find_one(post)

    if document:
        document_id = document['_id']
    else:
        document_id = collection.insert_one(post).inserted_id

    collection.update_one({'_id': document_id}, {"$set": {'last_updated': datetime.datetime.now()}, '$inc': {'count': 1}})

    return make_response('', 204)


if __name__ == "__main__":
    CONTEXT = SSLContext(PROTOCOL_TLSv1_2)
    CONTEXT.load_cert_chain('/etc/ssl/certs/ssl-cert-snakeoil.pem', '/etc/ssl/private/ssl-cert-snakeoil.key')
    APP.run(debug=True, host='0.0.0.0', port=443, ssl_context=CONTEXT)

