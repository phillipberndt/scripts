#!/usr/bin/env python3
# encoding: utf-8
import base64
import datetime
import fcntl
import json
import mimetypes
import os
import re
import uuid

from flask import Flask, request, Response, send_from_directory, jsonify, helpers
from jinja2 import Template

app = Flask(__name__)

from credentials import USER, PASSWORD

def new_auth_token(name=None):
    new_creds = str(uuid.uuid4())
    if name is None:
        name = "Credentials generated on %s" % datetime.datetime.now().strftime("%Y-%m-%d")
    with open("credentials.json", "a") as credentials_file:
        fcntl.lockf(credentials_file, fcntl.LOCK_EX)
        if credentials_file.tell() == 0:
            credentials = {}
        else:
            credentials_file.seek(0)
            credentials = json.load(credentials_file)
        credentials[new_creds] = name
        credentials_file.seek(0)
        credentials_file.truncate(0)
        json.dump(credentials, credentials_file)
    return new_creds

_valid_auth_token_cache = {}
def check_auth_token(token):
    if token not in _valid_auth_token_cache:
        try:
            with open("credentials.json", "r") as credentials_file:
                fcntl.lockf(credentials_file, fcntl.LOCK_SH)
                credentials = json.load(credentials_file)
        except FileNotFoundError:
            credentials = {}
        _valid_auth_token_cache[token] = token in credentials
    return _valid_auth_token_cache[token]

def auth(fn):
    def target_fn(*args, **kwargs):
        auth_ok = "fstore-cookie" in request.cookies and check_auth_token(request.cookies["fstore-cookie"])
        if not auth_ok:
            try:
                    auth_type, auth_data = request.headers["Authorization"].split()
                    assert auth_type == "Basic"
                    user, password = base64.b64decode(auth_data.encode("utf8")).decode().split(":", 1)
                    assert user == USER
                    assert password == PASSWORD
            except:
                rsp = Response()
                rsp.status_code = 401
                rsp.headers["WWW-Authenticate"] = "Basic realm=\"fstore\""
                rsp.data = "<h1>Authentication required</h1>"
                return rsp
        return fn(*args, **kwargs)
    target_fn.__name__ = fn.__name__
    return target_fn

@app.route("/e/<fn>")
@auth
def edit(fn):
    if not fn.endswith(".note") or ".." in fn or "/" in fn:
        raise "Forbidden"
    template = Template(open("note.html").read())
    try:
        note_data = open(os.path.join("data", fn)).read()
    except FileNotFoundError:
        note_data = ""
    return template.render(data=note_data, fn=fn)

@app.route("/f/<fn>")
@auth
def download(fn):
    return send_from_directory("data", fn, as_attachment=False)

@app.route("/upload", methods=("POST",))
@auth
def upload():
    if "file" in request.files:
        file_name = request.files["file"].filename
        if ".." in file_name or "/" in file_name:
            raise "Forbidden"
        request.files["file"].save(os.path.join("data", file_name))
    return jsonify(True)

@app.route("/upload_data", methods=("POST",))
@auth
def upload_data():
    file_name = request.values["file_name"]
    data = request.values["data"]
    if ".." in file_name or "/" in file_name:
        raise "Forbidden"
    target_file = os.path.join("data", file_name)
    with open(target_file, "wb") as out:
        out.write(data.encode("utf8"))
    return jsonify(True)

@app.route("/delete/<fn>", methods=("POST",))
@auth
def delete(fn):
    if ".." in fn or "/" in fn:
        raise "Forbidden"
    abs_path = os.path.join("data", fn)
    if not os.path.isfile(abs_path):
        return helpers.make_response("Not found", 404)
    os.unlink(abs_path)
    return jsonify(True)

@app.route("/rename", methods=("POST",))
@auth
def rename():
    fn_from = request.values["from"]
    fn_to = request.values["to"]

    if ".." in fn_from or "/" in fn_from or ".." in fn_to or "/" in fn_to:
        raise "Forbidden"
    fn_from_abs = os.path.join("data", fn_from)
    fn_to_abs = os.path.join("data", fn_to)
    if not os.path.isfile(fn_from_abs):
        return helpers.make_response("Not found", 404)
    os.rename(fn_from_abs, fn_to_abs)
    return jsonify(True)

@app.route("/perm-auth", methods=("POST",))
@auth
def perm_auth():
    name = request.values["name"]
    token = new_auth_token(name)
    rsp = Response()
    rsp.set_cookie("fstore-cookie", token, max_age=3600*24*30*6, secure=False)
    rsp.location = "./"
    rsp.status_code = 301
    return rsp

@app.route("/fs")
@auth
def get_fs():
    fs_py_contents = open("fs.py").read()
    my_url = "https://%s%s" % (request.host, request.path[:-2])
    body = re.sub("TARGET_URL = \"[^\"]+\"", "TARGET_URL = \"%s\"" % (my_url), fs_py_contents)
    return Response(body, mimetype="text/python")

def get_files():
    files = [ ]
    for fn in os.listdir("data"):
        stat = os.stat(os.path.join("data", fn))
        files.append({
            "name": fn,
            "mod_time": stat.st_mtime,
            "mod_time_str": datetime.datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    files.sort(key=lambda x: -x["mod_time"])
    return files

@app.route("/")
@auth
def index():
    template = Template(open("overview.html").read())
    files = get_files()
    return template.render(files=files, new_note_name=datetime.datetime.now().strftime("%Y-%m-%d_%H_%M_%S"))

@app.route("/list")
@auth
def list():
    files = get_files()
    return jsonify(files)

if __name__ == "__main__":
    app.run(threaded=True, use_reloader=True)
