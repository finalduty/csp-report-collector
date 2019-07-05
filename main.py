#!/usr/bin/env python3
""" CSP Report """

# Standard library imports
from argparse import ArgumentParser
from urllib.parse import urlparse
import datetime
import html
import os
import json
from ssl import PROTOCOL_TLSv1_2, SSLContext

# Third party library imports
from configparser import ConfigParser, NoOptionError, NoSectionError
from flask import Flask, jsonify, abort, make_response, request
from pymongo import MongoClient

# Debug
# from pdb import set_trace as st

APP = Flask(__name__)
VERSION = "%(prog)s 1.1.0"

def read_conf(conf_path):
    """
    Read CASSH configuration file and return metadata.
    """
    config = ConfigParser()
    config.read(conf_path)
    options = dict()
    options["main"] = dict()

    try:
        options["main"]["port"] = int(config.get("main", "port"))
        options["main"]["host"] = config.get("main", "host")
        options["main"]["debug"] = config.get("main", "debug") == "True"
    except (NoOptionError, ValueError) as error_msg:
        print("Can\"t read configuration file...")
        print(error_msg)
        exit(1)

    options["https"] = dict()
    if not config.has_option("https", "enable"):
        options["https"]["enable"] = False
    else:
        options["https"]["enable"] = config.get("https", "enable") == "True"
    if config.has_option("https", "pubkey"):
        options["https"]["pubkey"] = config.get("https", "pubkey")
        if not os.path.isfile(options["https"]["pubkey"]):
            print("{} is not a file".format(options["https"]["pubkey"]))
            exit(1)
    if config.has_option("https", "privkey"):
        options["https"]["privkey"] = config.get("https", "privkey")
        if not os.path.isfile(options["https"]["privkey"]):
            print("{} is not a file".format(options["https"]["privkey"]))
            exit(1)

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
        print("Can\"t read configuration file...")
        print(error_msg)
        exit(1)

    return options

@APP.errorhandler(400)  # 400 Bad Request
def error_400(error):
    return make_response(jsonify({
        "error": str(error)
    }), 400)


@APP.errorhandler(404)  # 404 Not Found
def error_404(error):
    return make_response(jsonify({
        "error": str(error)
    }), 404)


@APP.errorhandler(405)  # 405 Method Not Allowed
def error_405(error):
    return make_response(jsonify({
        "error": str(error),
    }), 405)


@APP.route("/", methods=["POST"])
def csp_receiver():
    ## https://junxiandoc.readthedocs.io/en/latest/docs/flask/flask_request_response.html
    if request.content_type != "application/csp-report":
        abort(400)

    csp_report = json.loads(request.data.decode("UTF-8"))["csp-report"]
    print(datetime.datetime.now(), request.remote_addr, request.content_type, csp_report)

    blocked_uri = html.escape(csp_report["blocked-uri"], quote=True).split(" ", 1)[0]
    document_uri = html.escape(csp_report["document-uri"], quote=True).split(" ", 1)[0]
    violated_directive = html.escape(csp_report["violated-directive"], quote=True).split(" ", 1)[0]
    #disposition = html.escape(csp_report["disposition"], quote=True)

    if blocked_uri == "about":
        return make_response("", 204)

    elif not blocked_uri:
        if violated_directive == "script-src":
            blocked_uri = "eval"

        elif violated_directive == "style-src":
            blocked_uri = "inline"
    if OPTIONS["mongodb"]["enable"]:
        domain = urlparse(document_uri).hostname
        collection = DB[domain]
        post = {"blocked_uri": blocked_uri, "violated_directive": violated_directive}

        document = collection.find_one(post)

        if document:
            document_id = document["_id"]
        else:
            document_id = collection.insert_one(post).inserted_id

        collection.update_one({"_id": document_id}, {"$set": {"last_updated": datetime.datetime.now()}, "$inc": {"count": 1}})

    return make_response("", 204)


if __name__ == "__main__":

    PARSER = ArgumentParser()
    PARSER.add_argument("--version", action="version", version=VERSION)
    PARSER.add_argument("-c", "--conf", action="store",\
        help="Configuration file.")

    ARGS = PARSER.parse_args()

    if ARGS.conf is None:
        print("You have to specify a configuration file")
        PARSER.print_help()
        exit(1)

    OPTIONS = read_conf(ARGS.conf)

    if OPTIONS["mongodb"]["enable"]:
        MONGO_CONNECTION_STRING = "mongodb://{}:{}".format(OPTIONS["mongodb"]["host"], OPTIONS["mongodb"]["port"])
        CLIENT = MongoClient(MONGO_CONNECTION_STRING, username=OPTIONS["mongodb"]["user"], password=OPTIONS["mongodb"]["pass"])
        DB = CLIENT[OPTIONS["mongodb"]["database"]]

    if OPTIONS["https"]["enable"]:
        CONTEXT = SSLContext(PROTOCOL_TLSv1_2)
        CONTEXT.load_cert_chain(OPTIONS["https"]["pubkey"], OPTIONS["https"]["privkey"])
        APP.run(debug=OPTIONS["main"]["debug"], host=OPTIONS["main"]["host"], port=OPTIONS["main"]["port"], ssl_context=CONTEXT)
    else:
        APP.run(debug=OPTIONS["main"]["debug"], host=OPTIONS["main"]["host"], port=OPTIONS["main"]["port"])

