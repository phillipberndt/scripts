#!/usr/bin/env python2
# encoding: utf-8
#
# fstore client
#
# TODO make py3 ready (remove urllib.quote)
#
from __future__ import print_function

import getpass
import os
import requests
import socket
import subprocess
import sys
import tempfile
import urllib

TARGET_URL = "http://localhost:5000/"

def auth_wrapper(request_fn, *args, **kw_args):
    credentials = None
    credentials_file_name = os.path.expanduser("~/.config/fstore")
    if os.path.isfile(credentials_file_name):
        with open(credentials_file_name, "r") as credentials_file:
            credentials = credentials_file.read().strip()
    if credentials:
        if "cookies" not in kw_args:
            kw_args["cookies"] = {}
        kw_args["cookies"]["fstore-cookie"] = credentials

    response = request_fn(*args, **kw_args)
    if response.status_code == 401:
        while response.status_code == 401:
            print("Unauthenticated.")
            user_name = raw_input("User name: ")
            password = getpass.getpass()
            response = requests.post("%sperm-auth" % (TARGET_URL,), {"name": "%s@%s" % (getpass.getuser(), socket.gethostname())}, auth=(user_name, password), allow_redirects=False)
        authentication_cookie = response.cookies["fstore-cookie"]
        with open(credentials_file_name, "w") as credentials_file:
            credentials_file.write(authentication_cookie)
        if "cookies" not in kw_args:
            kw_args["cookies"] = {}
        kw_args["cookies"]["fstore-cookie"] = credentials

        response = request_fn(*args, **kw_args)
    return response

def file_list():
    files = auth_wrapper(requests.get, "%slist" % (TARGET_URL,)).json()
    for file_obj in files:
        print("%s %s" % (file_obj["mod_time_str"], file_obj["name"]))

def get_file(name):
    stream = auth_wrapper(requests.get, "%sf/%s" % (TARGET_URL, urllib.quote(name)), stream=True)
    assert stream.status_code == 200
    for data in stream.iter_content(1024):
        yield data

def put_file(name, file_object):
    assert auth_wrapper(requests.post, "%supload" % (TARGET_URL,), files={"file": (name, file_object)}).status_code == 200

def rename_file(source_name, target_name):
    code = auth_wrapper(requests.post, "%srename" % (TARGET_URL,), data={"from": source_name, "to": target_name}).status_code
    if code == 404:
        print("File not found.", file=sys.stderr)
        return False
    assert code == 200
    return True

def unlink_file(file_name):
    code = auth_wrapper(requests.post, "%sdelete/%s" % (TARGET_URL, urllib.quote(file_name))).status_code
    if code == 404:
        print("File not found.", file=sys.stderr)
        return False
    assert code == 200
    return True

def help():
    print("Syntax: fs <action> [file name] [target file name]")
    print("Valid actions are ls, get, put, edit, mv, rm.")
    sys.exit(1)

def ask_overwrite(name):
    while True:
        print("File %s already exists. Overwrite? " % (name,), file=sys.stderr, end="")
        yes_no = raw_input()
        if not yes_no:
            continue
        if yes_no[0] == "y":
            return True
        elif yes_no[0] == "n":
            return False

if __name__ == "__main__":
    if len(sys.argv) == 1 or len(sys.argv) > 4:
        help()
    if sys.argv[1] == "help":
        help()
    elif sys.argv[1] == "ls":
        file_list()
    elif sys.argv[1] == "cat":
        for chunk in get_file(sys.argv[2]):
            sys.stdout.write(chunk)
    elif sys.argv[1] == "get":
        if len(sys.argv) > 3 and sys.argv[3] != "-":
            target = sys.argv[3]
        else:
            target = os.path.basename(sys.argv[2])
        if target == "-":
            target = sys.stdout
        else:
            if os.path.isfile(target) and not ask_overwrite(target):
                sys.exit(1)
            target = open(target, "wb")
        for chunk in get_file(sys.argv[2]):
            target.write(chunk)
    elif sys.argv[1] == "put":
        if len(sys.argv) > 3:
            target = sys.argv[3]
        else:
            target = os.path.basename(sys.argv[2])
        if sys.argv[1] == "-":
            source = sys.stdin
        else:
            source = open(sys.argv[2])
        put_file(target, source)
    elif sys.argv[1] == "mv":
        rename_file(sys.argv[2], sys.argv[3])
    elif sys.argv[1] == "rm":
        unlink_file(sys.argv[2])
    elif sys.argv[1] == "edit":
        temp_file = tempfile.NamedTemporaryFile(suffix=sys.argv[2])
        try:
            for chunk in get_file(sys.argv[2]):
                temp_file.write(chunk)
            temp_file.file.flush()
        except:
            pass
        subprocess.call([ os.environ.get("EDITOR", "vim"), temp_file.name ])
        while True:
            try:
                temp_file.file.seek(0)
                put_file(sys.argv[2], temp_file.file)
                break
            except:
                print("Failed to upload file from %s. Press <enter> to retry." % (sys.argv[2],))

    else:
        print("No such action.")
        help()
