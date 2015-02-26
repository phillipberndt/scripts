#!/usr/bin/env python
# encoding: utf-8
#
# Gigantic and monolitic http(s)d and ftpd and everything else that makes a move from b to c
# Copyright (c) 2015, Phillip Berndt
#
import SocketServer
import StringIO
import argparse
import atexit
import base64
import datetime
import email
import grp
import hashlib
import itertools
import logging
import mimetypes
import os
import pwd
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urlparse
import uuid
import tarfile

from wsgiref.handlers import format_date_time

# TODO ngrok support (?!)
# TODO htaccess/mod_rewrite support for httpd

try:
    import gtk
    has_gtk = True
except ImportError:
    has_gtk = False

try:
    import dbus
    has_dbus = True
except ImportError:
    has_dbus = False

try:
    from avahi import DBUS_NAME, DBUS_PATH_SERVER, DBUS_INTERFACE_SERVER, DBUS_INTERFACE_ENTRY_GROUP, PROTO_UNSPEC, IF_UNSPEC
except ImportError:
    DBUS_NAME = "org.freedesktop.Avahi"
    DBUS_PATH_SERVER = "/"
    DBUS_INTERFACE_SERVER = "org.freedesktop.Avahi.Server"
    DBUS_INTERFACE_ENTRY_GROUP = "org.freedesktop.Avahi.EntryGroup"
    PROTO_UNSPEC = -1
    IF_UNSPEC = -1

try:
    import ssl
    has_ssl = True
except:
    has_ssl = False

class SSLKey(object):
    "Tiny container for certificate information that can create self-signed temporary certificates on the fly"
    def __init__(self, cert=False, key=False):
        if (bool(cert) ^ bool(key)):
            raise ValueError("Either certificate or key not given")
        if cert and key:
            self.cert = cert
            self.key = key
        else:
            self._certfile = tempfile.NamedTemporaryFile()
            self._keyfile = tempfile.NamedTemporaryFile()
            subprocess.call(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-out", self._certfile.name, "-keyout", self._keyfile.name], stdout=open("/dev/null", "w"), stderr=open("/dev/null", "w"))
            self.key = self._keyfile.name
            self.cert = self._certfile.name
            logging.getLogger("main").info("SSL certificates created in %s (key) and %s (cert)", self.key, self.cert)

class ReusableServer(SocketServer.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, options={}):
        """Constructor.  May be extended, do not override."""
        self.__options = options
        SocketServer.ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass)

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        self.RequestHandlerClass(request, client_address, self, options=self.__options)

    def get_request(self):
        sock, client_address = SocketServer.ThreadingTCPServer.get_request(self)
        if "ssl_wrap" in self.__options:
            sock = ssl.wrap_socket(sock, self.__options["ssl_wrap"].key, self.__options["ssl_wrap"].cert, True, ssl_version = ssl.PROTOCOL_TLSv1 | ssl.PROTOCOL_SSLv23)
        return sock, client_address

class FtpHandler(SocketServer.StreamRequestHandler):
    """
        FTP server handler

        Specific options:
            - user: Username for authentication. If not set, any name is accepted.
            - pass: Password for authentication. If not set, no password is required.
            - write_access: Whether altering the file system is allowed

        Protocol information:
            http://tools.ietf.org/html/rfc959
            http://cr.yp.to/ftp/list/eplf.html

            This implementation should be RFC compliant. LIST output only has
            `ls' style output included, which some clients might not be able to
            parse. See the eplf link.
    """
    logger  = logging.getLogger("ftp")

    def __init__(self, request, client_address, server, options={}):
        self.user = None
        self.is_authenticated = False
        self.current_path = ""
        self.rest = 0
        self.rename_target = ""
        self.data_mode = { "mode": "PORT", "ip": client_address, "port": 20, "socket": None, "server_socket": None }

        self.options = options
        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)

    def log(self, lvl, msg, *args, **kwargs):
        kwargs.update({
            "ip": self.client_address[0],
        })
        self.logger.log(lvl, msg, kwargs)

    def reply(self, line):
        "Reply a status message in the `nnn Text' format. Multi-line messages are dealt with automatically."
        if "\r\n" in line:
            lines = line.split("\r\n")
            code, rest = lines[0].split(None, 1)
            lines = [ "%s-%s" % (code, rest) ] + lines[1:-1] + [ "%s %s" % (code, lines[-1]) ]
            self.wfile.write("%s\r\n" % "\r\n".join(lines))
        else:
            self.wfile.write("%s\r\n" % line)

    def connect_data_socket(self):
        "Establish a data connection to the client. Does not handle errors. Handles PASV/PORT for you."
        if not self.data_mode["socket"]:
            if self.data_mode["mode"] == "PORT":
                self.data_mode["socket"] = socket.socket()
                self.data_mode["socket"].connect((self.data_mode["ip"], self.data_mode["port"]))
            else:
                data_socket, remote = self.data_mode["server_socket"].accept()
                self.log(logging.DEBUG, "Data connection for %(target)s", target=self.client_address)
                self.data_mode["socket"] = data_socket

    def disconnect_data_socket(self):
        "Close any open data connection."
        if self.data_mode["socket"]:
            self.data_mode["socket"].shutdown(socket.SHUT_RDWR)
            self.data_mode["socket"] = None

    def reply_with_file(self, file, read_from_client=False):
        "Send a file to or receive a file from the client. `file' should be an open file object."
        self.reply("150 File status okay; about to open data connection.")
        try:
            self.connect_data_socket()
        except:
            self.reply("425 Can't open data connection.")
            return
        try:
            if self.rest:
                file.seek(self.rest)
            if read_from_client:
                fd_copy(self.data_mode["socket"].makefile("r"), file, -1)
            else:
                fd_copy(file, self.data_mode["socket"].makefile("w"), -1)
        except socket.error:
            self.reply("426 Connection closed; transfer aborted.")
            return
        self.reply("226 Closing data connection.")
        self.disconnect_data_socket()

    def build_path(self, path, expect="dir", must_exist=True):
        "Build a path suitable for open() from a user specified path. Replies an error message for you if the path is not allowed."
        if not path:
            return self.current_path
        if path[0] == '"' and path[-1] == '"':
            path = path[1:-1]
        if path[0] == "/":
            new_path = "%s/" % os.path.abspath(".%s" % path)
        else:
            new_path = "%s/" % os.path.abspath(os.path.join(self.current_path, path))
        base_path = "%s/" % os.path.abspath(".")
        if expect == "file":
            new_path = new_path[:-1]
            check = os.path.isfile
        elif expect == "any":
            if os.path.isdir(new_path):
                check = os.path.isdir
            else:
                new_path = new_path[:-1]
                check = os.path.isfile
        else:
            check = os.path.isdir
        if new_path[:len(base_path)] != base_path or (must_exist and not check(new_path)):
            self.reply("550 No such file or directory.")
            return False
        return new_path[len(base_path):]

    def generate_directory_listing(self, path):
        "Generate a `ls -l' style file listing and return it as a StringIO instance."
        response = StringIO.StringIO()
        if os.path.isdir(path or "."):
            target = os.listdir(path or ".")
        else:
            target = [ path ]
        for element in target:
            if element == path and len(target) == 1:
                file_path = path
            else:
                file_path = os.path.join(path, element)
            try:
                stat = os.stat(file_path)
            except:
                continue
            mtime = datetime.datetime.fromtimestamp(stat.st_mtime)
            response.write("%c%c%c%c%c%c%c%c%c%c 1 %s %s %13d %s %3s %s %s\r\n" % (
                "d" if os.path.isdir(file_path) else "-",
                "r" if stat.st_mode & 00400 else "-",
                "w" if stat.st_mode & 00200 else "-",
                "x" if stat.st_mode & 00100 else "-",
                "r" if stat.st_mode & 00040 else "-",
                "w" if stat.st_mode & 00020 else "-",
                "x" if stat.st_mode & 00010 else "-",
                "r" if stat.st_mode & 00004 else "-",
                "w" if stat.st_mode & 00002 else "-",
                "x" if stat.st_mode & 00001 else "-",
                pwd.getpwuid(stat.st_uid).pw_name,
                grp.getgrgid(stat.st_gid).gr_name,
                stat.st_size,
                mtime.strftime("%b"),
                mtime.strftime("%d"),
                mtime.strftime("%H:%I") if mtime.strftime("%Y") == datetime.datetime.today().strftime("%Y") else  mtime.strftime("%Y"),
                element))
        response.seek(0)
        return response

    def handle(self):
        self.log(logging.DEBUG, "Incoming FTP connection")
        self.reply("220 Service ready for new user.")
        while True:
            command = self.rfile.readline().strip()
            if not command:
                break
            self.log(logging.DEBUG, "Raw command: `%(command)s'", {"command": command })
            command = command.split(None, 1)

            # Authentication and unauthenticated commands
            if command[0] == "USER":
                if "user" in self.options and self.options["user"] and command[1] != self.options["user"]:
                    self.reply("430 Invalid username or password")
                elif "pass" in self.options and self.options["pass"]:
                    self.reply("331 User name okay, need password.")
                    self.user = command[1]
                else:
                    self.reply("230 User logged in, proceed.")
                    self.user = command[1]
                    self.log(logging.INFO, "%(user)s logged in.", user=self.user)
                    self.is_authenticated = True
                continue
            elif command[0] == "PASS" and self.user:
                if "pass" in self.options and command[1] != self.options["pass"]:
                    self.reply("430 Invalid username or password")
                else:
                    self.reply("230 User logged in, proceed.")
                    self.log(logging.INFO, "%(user)s logged in.", user=self.user)
                    self.is_authenticated = True
                continue
            elif command[0] in ("NOOP", "ALLO"):
                self.reply("200 No operation.")
                continue
            elif command[0] == "SYST":
                self.reply("215 UNIX")
                continue
            elif command[0] == "QUIT":
                self.reply("221 Goodbye")
                break
            else:
                if not self.is_authenticated:
                    self.reply("530 Not logged in")
                    continue

            # Commands that do not require write permissions
            if command[0] == "TYPE":
                self.reply("202 Command not implemented, superfluous at this site.")
                continue
            elif command[0] == "MODE":
                if command[1] != "Stream":
                    self.reply("504 Command not implemented for that parameter.")
                else:
                    self.reply("200 Fine with me")
                continue
            elif command[0] == "STRU":
                if command[1] != "F":
                    self.reply("504 Command not implemented for that parameter.")
                else:
                    self.reply("200 Fine with me")
                continue
            elif command[0] in ("PASV", "PORT"):
                for which in ("socket", "server_socket"):
                    if self.data_mode[which]:
                        self.data_mode[which].shutdown(socket.SHUT_RDWR)
                        self.data_mode[which] = None
                if command[0] == "PASV":
                    server_socket, port = setup_tcp_server_socket(1234 if "pasv_port" not in self.options else self.options["pasv_port"])
                    server_socket.listen(1)
                    self.data_mode = { "mode": "PASV", "ip": self.request.getsockname()[0], "port": port, "socket": None, "server_socket": server_socket }
                    self.reply("227 Entering Passive Mode (%s,%d,%d)." % (self.data_mode["ip"].replace(".", ","), (self.data_mode["port"] & 0xFF00) >> 8, (self.data_mode["port"] & 0x00FF)))
                else:
                    port = command[1].split(",")
                    self.data_mode = { "mode": "PORT", "ip": "%s.%s.%s.%s" % tuple(port[:4]), "port": (int(port[4]) << 8) + int(port[5]), "socket": None, "server_socket": None }
                    self.reply("200 PORT command successful, connecting to %s:%d" % (self.data_mode["ip"], self.data_mode["port"]))
                continue
            elif command[0] in ("LIST", "STAT", "NLST"):
                if len(command) > 1:
                    path_components = [ x for x in command[1].split(" ") if x[0] != "-" ]
                    path_string = " ".join(path_components)
                    path = self.build_path(path_string, expect="any")
                    if path == False:
                        continue
                else:
                    path = self.current_path

                self.log(logging.INFO, "%(command)s %(path)s", command=command[0], path=path)

                if command[0] == "NLST":
                    response = StringIO.StringIO()
                    response.write("\r\n".join(os.listdir(path or ".")))
                    response.seek(0)
                else:
                    response = self.generate_directory_listing(path)
                if command[0] == "STAT":
                    self.reply("213 Status follows:\r\n%s\r\nEnd of status" % response.buf)
                else:
                    self.reply_with_file(response)
                continue
            elif command[0] == "SIZE":
                target = self.build_path(command[1], expect="file")
                if not target:
                    continue
                self.reply("213 %d" % os.stat(target).st_size)
                continue
            elif command[0] == "PWD":
                self.reply("257 \"/%s\"" % self.current_path)
                continue
            elif command[0] == "CWD":
                new_path = self.build_path(command[1])
                if new_path == False:
                    continue
                self.current_path = new_path
                self.reply("200 \"/%s\"" % self.current_path)
                continue
            elif command[0] == "RETR":
                which_file = self.build_path(command[1], expect="file")
                if which_file == False:
                    continue
                self.log(logging.INFO, "%(command)s %(path)s", command=command[0], path=which_file)
                self.reply_with_file(open(which_file, "r"))
                continue
            elif command[0] == "CDUP":
                self.current_path = "/".join(self.current_path.split("/")[:-1])
                self.reply("200 \"/%s\"" % self.current_path)
                continue
            elif command[0] == "REST":
                self.rest = int(command[1])
                self.reply("350 Restart position accepted (%d)" % (self.rest, ))
                continue
            elif command[0] == "ABOR":
                self.reply("202 This server only supports abort by closing the socket on your end")
                continue
            else:
                if "write_access" not in self.options or not self.options["write_access"]:
                    self.reply("502 Command not implemented.")
                    continue

            # Commands that alter the file system
            if command[0] in ("STOR", "STOU", "APPE"):
                target_file = self.build_path(command[1], expect="file", must_exist=False)
                if not target_file:
                    continue
                if command[0] == "STOU" and os.path.exists(target_file):
                    self.reply("450 Requested file action not taken.")
                    continue
                self.log(logging.INFO, "%(command)s %(path)s", command=command[0], path=target_file)
                try:
                    target = open(target_file, "w" if command[0] != "APPE" else "a")
                except:
                    self.reply("550 Requested action not taken.")
                    continue

                self.reply_with_file(target, read_from_client=True)
                continue
            elif command[0] == "RNFR":
                target_file = self.build_path(command[1], expect="any")
                if not target_file:
                    continue
                self.rename_target = target_file
                continue
            elif command[0] == "RNTO":
                if not self.rename_target:
                    self.reply("350 Requested file action pending further information.")
                    continue
                target = self.build_path(command[1], expect="file", must_exist=False)
                if not target:
                    continue
                try:
                    os.rename(self.rename_target, target)

                    self.log(logging.INFO, "Rename %(source) -> %(target)s", source=self.rename_target, target=target)
                    self.reply("250 Requested file action okay, completed.")
                except:
                    self.reply("553 Requested action not taken.")
                self.rename_target = ""
                continue
            elif command[0] in ("DELE", "RMD"):
                target = self.build_path(command[1], expect="file" if command[0] == "DELE" else "dir")
                if not target:
                    continue
                try:
                    if command[0] == "DELE":
                        os.unlink(target)
                    else:
                        os.rmdir(target)
                    self.log(logging.INFO, "%(command)s %(path)s", command=command[0], path=target)
                    self.reply("250 Requested file action okay, completed.")
                except:
                    self.reply("553 Requested action not taken.")
                continue
            elif command[0] == "MKD":
                target = self.build_path(command[1], expect="dir", must_exist=False)
                if not target:
                    continue
                try:
                    os.mkdir(target)
                    self.log(logging.INFO, "%(command)s %(path)s", command=command[0], path=target)
                    self.reply("257 \"%s\" created." % target)
                except:
                    self.reply("553 Requested action not taken.")
                continue
            elif command[0] == "SITE":
                sub = command[1].split(None, 3)
                if sub[0] == "CHMOD":
                    mode = int(sub[1].rjust(5, "0"), 8)
                    target = self.build_path(sub[2], expect="any")
                    if not target:
                        return
                    os.chmod(target, mode)
                    self.reply("250 Requested file action okay, completed.")
                else:
                    self.reply("502 Command not implemented.")
                continue
            else:
                self.reply("502 Command not implemented.")
                continue

class ChunkWrapper(object):
    "Context-Wrapper around a file-like object that intercepts calls to write() and outputs chunks instead"
    def __init__(self, fileobj):
       self.fileobj = fileobj

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.fileobj.write("0\r\n\r\n")

    def write(self, data):
        self.fileobj.write("%x\r\n%s\r\n" % (len(data), data))

    def flush(self):
        self.fileobj.flush()

    def truncate(self):
        pass

    def writelines(self, lines):
        for line in lines:
            self.write("%s\n" % line)

    def close(self):
        pass

class HttpHandler(SocketServer.StreamRequestHandler):
    """
        HTTP server

        Specific options:
            currently none

        Protocol information:
            Written from experience, not following the RFC litereally. Supports
                - Range requests
                - Chunked encoding
                - Keep-Alive
                - Directory listings (with fancy icons!)
            Support is TODO for
                - Compression
    """
    timeout = 10
    logger  = logging.getLogger("http")

    def log(self, lvl, msg, *args, **kwargs):
        kwargs.update({
            "ip": self.client_address[0],
        })
        self.logger.log(lvl, msg, kwargs)

    def __init__(self, request, client_address, server, options={}):
        self.headers = {}
        self.http_version = "HTTP/1.1"
        self.options = options
        if not "_http_active_nonces" in options:
            options["_http_active_nonces"] = {}
        self.active_nonces = options["_http_active_nonces"]
        self.body_read = False
        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)

    def setup(self):
        SocketServer.StreamRequestHandler.setup(self)
        self.processing_started = time.time()

    def read_http_method(self):
        "Read the first line of an HTTP request"
        line = self.rfile.readline()
        if not line:
            return False
        self.method, self.path, self.http_version = line.split()
        if self.http_version.lower() not in ("http/1.1", "http/1.0"):
            raise RuntimeError("Unknown HTTP version %s" % (self.http_version, ))
        return True

    def read_http_headers(self):
        r"Read all HTTP headers until \r\n"
        previous_header = None
        while True:
            line = self.rfile.readline()
            line = line[:-2 if line[-2] == "\r" else -1]
            if not line:
                return
            if line[0].isspace():
                self.headers[previous_header][-1] += " %s" % (line.strip(), )
            previous_header, value = line.split(":", 1)
            previous_header = previous_header.lower()
            if previous_header not in self.headers:
                self.headers[previous_header] = []
            self.headers[previous_header].append(value.strip())

    def read_http_body(self, target_file=None):
        "Read the body of a request. Safe to call twice, as this function memorizes whether the body has been read."
        if self.body_read:
            return
        if "expect" in self.headers and "100-continue" in self.headers["expect"]:
            self.wfile.write("%s 100 Continue\r\n\r\n" % self.http_version)
        if "content-length" in self.headers:
            bytes_to_read = int(self.headers["content-length"][0])
            fd_copy(self.rfile, target_file, bytes_to_read)
        elif "transfer-encoding" in self.headers:
            if self.headers["transfer-encoding"][0] is not "chunked":
                raise ValueError("Unsupported transfer encoding: %s" % self.headers["transfer-encoding"][0])
            while True:
                chunk_size = int(self.rfile.readline(), 16)
                if chunk_size == 0:
                    break
                fd_copy(self.rfile, target_file, chunk_size)
            self.read_http_headers()
        self.body_read = True

    def send_header(self, status, headers):
        "Send the headers of a reply."
        self.log(logging.INFO, "%(status)s %(method)s %(path)s", status=status.split()[0], method=self.method, path=self.path)

        if "Host" not in headers:
            headers["Host"] = self.headers["host"][0] if "host" in self.headers else socket.gethostbyname()
        if "Connection" not in headers:
            headers["Connection"] = self.headers["connection"][0] if "connection" in self.headers else ("Keep-Alive" if self.http_version.lower() == "http/1.1" else "Close")
        headers_list = []
        for name, value in headers.items():
            if type(value) is list:
                for svalue in value:
                    headers_list.append("%s: %s" % (name, svalue))
            else:
                headers_list.append("%s: %s" % (name, value))
        self.wfile.write("%s %s\r\n%s\r\n\r\n" % (self.http_version, status, "\r\n".join(headers_list)))

    def send_error(self, error_message, force_close=False, details="", headers={}):
        "Reply with an error message. After calling this, you can safely return from any handler."
        if ("content-length" in self.headers or "transfer-encoding" in self.headers) and not ("expect" in self.headers and "100-continue" in self.headers["expect"]):
            force_close = True
        if force_close:
            self.headers["connection"] = [ "close" ]
        body = "<!DOCTYPE HTML><title>%s</title><body><h1>%s</h1><pre>%s</pre>" % (error_message, error_message, xml_escape(details))
        headers.update({ "Content-Length": len(body), "Content-Type": "text/html" })
        self.send_header(error_message, headers)
        self.wfile.write(body)

    def handle_request_for_cgi(self):
        "Like handle_request_for_file, but run the target file as a CGI script"
        file_extension = os.path.splitext(self.mapped_path)[-1][1:]
        if file_extension in self.options["cgi_handlers"]:
            execute = [ self.options["cgi_handlers"][file_extension], self.mapped_path ]
        else:
            execute = [ self.mapped_path ]

        environ = os.environ.copy()
        environ.update({
                "SERVER_SOFTWARE": "ihttpd",
                "SERVER_NAME": self.headers["host"][0] if "host" in self.headers else socket.gethostname(),
                "GATEWAY_INTERFACE": "CGI/1.1",
                "SERVER_PROTOCOL": self.http_version,
                "SERVER_PORT": str(self.request.getsockname()[1]),
                "REQUEST_METHOD": self.method,
                "QUERY_STRING": urlparse.urlparse(self.path).query,
                "SCRIPT_NAME": self.mapped_path,
                "PATH_INFO": self.mapped_path,
                "REQUEST_URI": self.path,
                "PATH_TRANSLATED": os.path.abspath(self.mapped_path),
                "REMOTE_ADDR": self.request.getpeername()[0],
                "CONTENT_TYPE": self.headers["content-type"][0] if "content-type" in self.headers else "",
                "CONTENT_LENGTH": str(self.headers["content-length"][0]) if "content-length" in self.headers else "0"
        })
        for header in self.headers:
            environ["HTTP_%s" % header.upper().replace("-", "_")] = ", ".join(self.headers[header])

        cgi_process = subprocess.Popen(execute, stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True, env=environ)

        def _read_body_to_cgi():
            try:
                self.read_http_body(cgi_process.stdin)
                cgi_process.stdin.close()
            except:
                self.send_error("500 Internal server error", True)
        threading.Thread(target=_read_body_to_cgi).start()

        cgi_headers = {}
        last_header = None
        while True:
            cgi_header = cgi_process.stdout.readline()
            if not cgi_header:
                self.send_error("500 Internal server error", True)
                cgi_process.terminate()
                return
            cgi_header = cgi_header[:-1]
            if cgi_header and cgi_header[-1] == "\r":
                cgi_header = cgi_header[:-1]
            if not cgi_header:
                break
            if cgi_header[0].isspace():
                cgi_headers[last_header].append(cgi_header.strip())
            else:
                last_header, value = cgi_header.split(":", 1)
                last_header = last_header.lower()
                cgi_headers[last_header] = [ value.strip() ]

        status = "200 Ok" if "status" not in cgi_headers else cgi_headers["status"][0]
        headers = { ucparts(key): ", ".join(value) for key, value in cgi_headers.items() if key != "status" }
        if "Content-Type" not in headers:
            headers["Content-Type"] = "text/html"

        if "content-length" in cgi_headers:
            self.send_header(status, headers)
            fd_copy(cgi_process.stdout, self.wfile, int(cgi_headers["content-length"]))
        else:
            headers["Transfer-Encoding"] = "chunked"
            self.send_header(status, headers)
            with ChunkWrapper(self.wfile) as wfile:
                fd_copy(cgi_process.stdout, wfile, -1)
        cgi_process.terminate()

    def handle_request_for_file(self):
        "Handle a request for a file, simple GET/HEAD/POST case."
        if os.path.isdir(self.mapped_path):
            request = urlparse.urlparse(self.path)
            query = urlparse.parse_qs(request.query)
            path = request.path

            if "action" in query and query["action"][0] == "download":
                archive_name = os.path.basename(path).replace('"', r'\"') or "download"
                self.send_header("200 Ok", { "Content-Type": "application/x-gtar", "Content-Disposition": "attachment; filename=\"%s.tar.bz2\"" % archive_name, "Transfer-Encoding": "chunked" })
                with ChunkWrapper(self.wfile) as wfile:
                    outfile = tarfile.open(mode="w|bz2", fileobj=wfile, format=tarfile.USTAR_FORMAT)
                    outfile.add(self.mapped_path, "")
                    outfile.close()
                return

            if "write_access" in self.options and "content-type" in self.headers:
                body = StringIO.StringIO()
                body.write("Content-Type: %s\r\n\r\n" % (self.headers["content-type"][0]))
                self.read_http_body(body)
                msg = email.message_from_string(body.getvalue())
                is_upload = False
                for part in msg.get_payload():
                    if "upload" in part.get("content-disposition", "") and part.get_payload() == "Upload":
                        is_upload = True
                        break
                if is_upload:
                    for part in msg.get_payload():
                        disposition = part.get("content-disposition", "")
                        filename = re.search(r'filename="((?:[^"]|\")+)"', disposition)
                        if filename:
                            filename = filename.group(1).replace(r'\"', '"')
                            self.logger.info("Received file %(filename)s", { "filename": filename })
                            if not "/" in filename:
                                with open(os.path.join(self.mapped_path, filename), "w") as outfile:
                                    outfile.write(part.get_payload())
                    self.send_header("302 Found", { "Location": path, "Content-Length": 0 })
                    return

            mime_type = "text/html; charset=utf8"
            data = [ """<!DOCTYPE HTML><meta charset=utf8><title>Directory contents for %(path)s</title><style type='text/css'>
                    body { font-size: 12px; font-family: sans-serif; }
                    img { vertical-align: middle; }
                    ul, li { list-style-type: none; }
                    a { font-weight: bold; }
                </style><body><h1>Directory contents for %(path)s</h1><p>Directory: <a href="/">root</a> """ % { "path": xml_escape(urldecode(path)) } ]

            full_dirspec = "/"
            for dirspec in urldecode(path).split("/"):
                if not dirspec:
                    continue
                full_dirspec = "%s%s/" % (full_dirspec, dirspec)
                data.append('&raquo; <a href="%s">%s</a>' % (full_dirspec, dirspec))
            data.append(' (<a href="?action=download">Download as TAR.BZ2</a>)')
            data.append("</p><ul>")

            base = path + ("/" if path[-1] != "/" else "")
            dirs = []
            files = []

            for name in sorted(os.listdir(self.mapped_path), key=natsort_key):
                if name[0] == ".":
                    continue
                absname = os.path.join(self.mapped_path, name)
                if os.path.isdir(absname):
                    if has_gtk:
                        dirs.append("<li><img src='/.directory-icons/inode-directory'> <a href='%s/'>%s</a> <em>Folder</em></li>" % (xml_escape(os.path.join(base, name)), xml_escape(name)))
                    else:
                        dirs.append("<li><a href='%s/'>%s</a> <em>Folder</em></li>" % (xml_escape(os.path.join(base, name)), xml_escape(name)))
                else:
                    try:
                        file_mime_type = mimetypes.guess_type(absname)[0] or "application/octet-stream"
                        size = format_size(os.stat(absname).st_size)
                    except:
                        size = 0
                    if has_gtk:
                        if not gtk.icon_theme_get_default().has_icon(file_mime_type.replace("/", "-")):
                            file_mime_type = "application-octet-stream"
                        files.append("<li><img src='/.directory-icons/%s'> <a href='%s'>%s</a> <em>%s</em></li>" % (file_mime_type.replace("/", "-"), xml_escape(os.path.join(base, name)), xml_escape(name), size))
                    else:
                        files.append("<li><a href='%s'>%s</a> <em>%s</em></li>" % (xml_escape(os.path.join(base, name)), xml_escape(name), size))

            data += dirs
            data += files
            data.append("</ul>")
            if "write_access" in self.options:
                data.append('<form method="post" enctype="multipart/form-data"><h2>Upload</h2><input type=file multiple name=file><input type=submit name=upload value="Upload"></form>')
            data.append("</body>")
            data = "\r\n".join(data)
            size = len(data)
            file = StringIO.StringIO(data)
        else:
            if "allow_cgi" in self.options and self.options["allow_cgi"] and (os.path.splitext(self.mapped_path)[-1][1:] in self.options["cgi_handlers"] or os.access(self.mapped_path, os.X_OK)):
                self.handle_request_for_cgi()
                return
            mime_type = mimetypes.guess_type(self.mapped_path)[0]
            stat = os.stat(self.mapped_path)
            size = stat.st_size
            file = open(self.mapped_path, "rb")

        status = "200 Ok"
        self.read_http_body()
        self.reply_with_file_like_object(file, size, mime_type, status)

    def reply_with_file_like_object(self, file, size, mime_type, status, additional_headers={}):
        "Reply to a request with a file object"
        start = 0
        headers = additional_headers.copy()
        if size > 0:
            if "range" in self.headers:
                req_range_type, req_range = self.headers["range"][0].split("=")
                range_start, range_end = req_range.split("-")
                range_start = int(range_start) if range_start else 0
                range_end = int(range_end) if range_end else (size - 1)
                if req_range_type.lower() != "bytes" or range_start < 0 or range_end < range_start or range_end > size:
                    self.send_error("416 Range Not Satisfiable")
                    return
                status = "206 Partial Content"
                headers["Content-Range"] = "bytes %d-%d/%d" % (range_start, range_end, size)
                start = range_start
                size = range_end - range_start + 1

            file.seek(start)
            headers["Accept-Ranges"] = "bytes"
            headers["Content-Length"] = size
        else:
            headers["Transfer-Encoding"] = "chunked"

        headers["Content-Type"] = mime_type
        self.send_header(status, headers)
        if self.method.lower() != "head":
            if size < 0:
                with ChunkWrapper(self.wfile) as wfile:
                    fd_copy(file, wfile, size)
            else:
                fd_copy(file, self.wfile, size)
        file.close()

    def handle_dav_request(self):
        "Handle webdav specific methods."
        method = self.method.upper()
        if method == "OPTIONS":
            self.read_http_body()
            self.send_header("200 Ok", {
                "Allow": "OPTIONS, GET, HEAD, POST, PUT, DELETE, COPY, MOVE, MKCOL, PROPFIND" if "write_access" in self.options and self.options["write_access"] else "OPTIONS, GET, HEAD, POST, PUT, PROPFIND",
                "DAV": "1, 2, ordered-collections",
                "Content-Length": 0 })
        elif method == "PROPFIND":
            self.read_http_body()
            response = StringIO.StringIO()
            response.write("<?xml version='1.0' encoding='utf-8'?>\r\n<D:multistatus xmlns:D='DAV:'>")
            if os.path.isdir(self.mapped_path):
                if "depth" in self.headers and self.headers["depth"][0] == "0":
                    collection = [""]
                elif "depth" in self.headers and self.headers["depth"][0] != "1":
                    self.send_error("413 Request Entity Too Large")
                    return
                else:
                    collection = itertools.chain([""], os.listdir(self.mapped_path))
                for file_name in collection:
                    file_path = os.path.join(self.mapped_path, file_name)
                    try:
                        stat = os.stat(file_path)
                    except:
                        continue
                    if os.path.isdir(file_path):
                        res_type = "<D:resourcetype><D:collection/></D:resourcetype>"
                    else:
                        res_type = "<D:resourcetype/><D:getcontentlength>%d</D:getcontentlength>" % (stat.st_size, )
                    response.write("<D:response><D:href>%s%s%s</D:href><D:propstat><D:prop>%s</D:prop><D:status>HTTP/1.1 200 Ok</D:status></D:propstat></D:response>\r\n" % (self.path, "/" if self.path[-1] != "/" else "", file_name, res_type))
            else:
                try:
                    stat = os.stat(self.mapped_path)
                except:
                    self.send_error("404 Not found")
                    return
                response.write(("<D:response><D:href>%s</D:href><D:propstat><D:prop>"
                                "<D:resourcetype/><D:getcontentlength>%d</D:getcontentlength>"
                                "<D:creationdate>%s</D:creationdate><D:getlastmodified>%s</D:getlastmodified><D:getcontenttype>%s</D:getcontenttype>"
                                "</D:prop><D:status>HTTP/1.1 200 Ok</D:status></D:propstat></D:response>") %
                               (self.path, stat.st_size, iso_time(stat.st_ctime), format_date_time(stat.st_mtime), mimetypes.guess_type(self.path)[0] or "application/octet-stream"))
            response.write("</D:multistatus>\r\n")
            response.seek(0)
            self.reply_with_file_like_object(response, len(response.buf), "text/xml; charset=utf-8", "207 Multi-Status")
        elif not "write_access" in self.options or not self.options["write_access"]:
            self.read_http_body()
            self.send_error("405 Method not allowed")
        elif method == "PUT":
            try:
                target_file = open(self.mapped_path, "w")
                self.read_http_body(target_file)
                self.send_header("201 Created", { "Content-Length": 0 })
            except:
                self.send_error("403 Access denied")
        elif method == "MKCOL":
            try:
                self.read_http_body()
                os.mkdir(self.mapped_path)
                self.send_header("201 Created", { "Content-Length": 0 })
            except:
                self.send_error("403 Access denied")
        elif method == "MOVE":
            target = self.map_url(self.headers["destination"][0])
            if not target:
                self.send_error("400 Malformed request, destination missing")
                return
            try:
                self.read_http_body()
                os.rename(self.mapped_path, target)
                self.send_header("200 Ok", { "Content-Length": 0 })
            except:
                self.send_error("403 Access denied")

            pass
        elif method == "COPY":
            target = self.map_url(self.headers["destination"][0])
            if not target:
                self.send_error("400 Malformed request, destination missing")
                return
            try:
                shutil.copytree(self.mapped_path, target)
                self.send_header("200 Ok", { "Content-Length": 0 })
            except:
                self.send_error("403 Access denied")
        elif method == "DELETE":
            try:
                if os.path.isdir(self.mapped_path):
                    shutil.rmtree(self.mapped_path)
                else:
                    os.unlink(self.mapped_path)
                self.send_header("200 Ok", { "Content-Length": 0 })
            except:
                self.send_error("403 Access denied")
            pass
        else:
            self.send_error("405 Method not allowed")

    def map_url(self, url_arg):
        "Map an URL (or path of an URL) to a local file"
        url = urlparse.urlparse(url_arg)
        path = re.sub("^/+", "", urldecode(url.path))
        cwd = os.path.abspath(".")
        mapped_path = os.path.join(cwd, path)
        if mapped_path[:len(cwd)] != cwd:
            return False
        return mapped_path

    def generate_nonce(self):
        "Generate a nonce for Digest authentication"
        nonce = uuid.uuid4().hex
        self.active_nonces[nonce] = { "time": time.time(), "used_nc": [] }
        return nonce

    def handle_request(self):
        "Handle a single request."
        self.body_read = False
        if not self.read_http_method():
            self.rfile.close()
            return
        self.headers = {}
        self.read_http_headers()
        if "host" not in self.headers:
            self.headers["host"] = [ socket.gethostname() ]

        if "user" in self.options and self.options["user"]:
            # Authenticate the user
            authentication_ok = False
            is_stale = False
            if "authorization" in self.headers:
                method, param = self.headers["authorization"][0].split(None, 1)
                if method.lower() == "basic":
                    user, password = base64.b64decode(param).split(":", 1)
                    if user == self.options["user"] and password == self.options["pass"]:
                        authentication_ok = True
                elif method.lower() == "digest":
                    params = {}
                    for partial_param in param.split(","):
                        name, value = partial_param.strip().split("=", 1)
                        if value[0] == '"' and value[-1] == '"':
                            value = value[1:-1]
                        params[name] = value
                    if params["nonce"] in self.active_nonces and self.active_nonces[params["nonce"]]["time"] > time.time() - 600:
                        data = self.active_nonces[params["nonce"]]
                        ha1 = hashlib.md5("%s:%s:%s" % (params["username"], params["realm"], self.options["pass"])).hexdigest()
                        ha2 = hashlib.md5("%s:%s" % (self.method, params["uri"])).hexdigest()
                        response = hashlib.md5("%s:%s:%s:%s:%s:%s" % (ha1, params["nonce"], params["nc"], params["cnonce"], params["qop"], ha2)).hexdigest()
                        self.logger.debug("Digest authentication: Excpected %(expect)s, received %(received)s", {"expect": response, "received": str(params)})
                        if params["nc"] not in data["used_nc"] and response == params["response"] and params["username"] == self.options["user"]:
                            # Testing for nc > last_nc (base 16!) suffices in
                            # theory, but due to the thread-bases approach I
                            # use here it doesn't. Also, note that there's a race
                            # condition here.
                            data["used_nc"].append(params["nc"])
                            authentication_ok = True
                    else:
                        is_stale = True
            if not authentication_ok:
                digest_authentication_challenge = ", ".join([
                   'Digest realm="megad webserver"',
                   'qop="auth"',
                   'nonce="{nonce}"',
                   'opaque="0"',
                ]).format(nonce=self.generate_nonce())
                if is_stale:
                    digest_authentication_challenge += ", stale=TRUE"
                self.send_error("401 Not Authorized", headers={ "WWW-Authenticate": [ digest_authentication_challenge, 'Basic realm="megad webserver"' ] })
                return

        if self.path.startswith("/.directory-icons/") and has_gtk:
            output = StringIO.StringIO()
            def send_data(buf, data=None):
                    output.write(buf)
                    return True
            gtk.icon_theme_get_default().load_icon(self.path[18:], 32, 0).save_to_callback(send_data, "png", {}, None)
            self.reply_with_file_like_object(output, output.pos, "image/png", "200 Ok")
            return

        self.mapped_path = self.map_url(self.path[1:])
        if not self.mapped_path:
            self.send_error("403 Access denied")
            return

        if "dav_enabled" in self.options and self.options["dav_enabled"] and self.method.upper() in ("PUT", "MKCOL", "DELETE"):
            self.handle_dav_request()
            return

        if not os.path.exists(self.mapped_path):
            self.send_error("404 Not found")
            return

        if "dav_enabled" in self.options and self.options["dav_enabled"] and self.method.upper() in ("OPTIONS", "PROPFIND", "MOVE", "COPY"):
            self.handle_dav_request()
            self.read_http_body()
            return

        if self.method.lower() not in ("get", "post"):
            self.send_error("405 Method not allowed")

        if os.path.isdir(self.mapped_path):
            for index_candidate in ("index.html", "index.htm", "index.php"):
                candidate = os.path.join(self.mapped_path, index_candidate)
                if os.path.isfile(candidate):
                    self.mapped_path = candidate

        self.handle_request_for_file()

    def handle(self):
        self.log(logging.DEBUG, "Accepted connection")
        while not self.rfile.closed:
            try:
                self.handle_request()
            except socket.error:
                break
            except Exception as e:
                self.log(logging.ERROR, "Exception %(exception_info)s", exception_info="".join(traceback.format_exc()))
                try:
                    self.send_error("500 Internal Server Error", True, details=str(e))
                except socket.error:
                    pass
                break
            if "connection" in self.headers:
                if self.headers["connection"][0].lower() != "keep-alive":
                    break
            elif not self.http_version or self.http_version.lower() == "http/1.0":
                break

    def finish(self):
        try:
            SocketServer.StreamRequestHandler.finish(self)
        except:
            pass

def xml_escape(string):
    "Escape special XML/HTML characters"
    return string.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def format_size(size):
    "Format a human-readable file size"
    prefix = ""
    for prefix in ("", "K", "M", "G", "T"):
        if size < 1024:
            break
        size /= 1024.
    return "%2.2f %sBi" % (size, prefix)

def fd_copy(source_file, target_file, length):
    "Copy length bytes from source_file to target_file"
    def _read(amount):
        if type(source_file) is not socket._fileobject and hasattr(source_file, "fileno"):
            return os.read(source_file.fileno(), amount)
        else:
            return source_file.read(amount)

    buffer = 10240
    if length < 0:
        while True:
            data = _read(buffer)
            if not data:
                break
            if target_file:
                target_file.write(data)
    else:
        while length > 0:
            data = _read(min(buffer, min(length, 10240)))
            if not data:
                raise IOError("Failed to read data")
            if target_file:
                target_file.write(data)
            length -= len(data)

def setup_tcp_server(handler_class, base_port=("", 1234), options={}):
    "Setup a SocketServer on a variable path. Returns the instance and the actual port as a tuple."
    counter = 0
    while True:
        try:
            server = ReusableServer((base_port[0], base_port[1] + counter), handler_class, options=options)
            break
        except socket.error:
            counter += 1
            if counter > 100:
                raise
    threading.Thread(target=server.serve_forever).start()
    return server, (base_port[0] or "*", base_port[1] + counter)

def setup_tcp_server_socket(base_port=1234):
    "Setup a TCP socket on a variable path. Returns the instance and the actual port as a tuple."
    counter = 0
    while True:
        try:
            server = socket.socket()
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('', base_port + counter))
            break
        except socket.error:
            counter += 1
            if counter > 100:
                raise
    return server, base_port + counter

def wait_for_signal(servers):
    """Infinite loop that intercepts <C-c>, closes the servers if it catches it
    once and kills the process the second time."""
    signal_count = [ 0 ]
    def _signal_handler(signum, frame):
        signal_count[0] += 1
        if signal_count[0] == 1:
            logging.warn("Signal received. Shutting down server sockets.")
            for server in servers:
                server.shutdown()
                server.socket.shutdown(socket.SHUT_RDWR)
                server.socket.close()
                del server.socket
        else:
            logging.warn("Second signal received. Killing the process.")
            os.closerange(3, 255)
            os.kill(os.getpid(), signal.SIGKILL)
    oldint = signal.signal(signal.SIGINT, _signal_handler)
    oldhup = signal.signal(signal.SIGHUP, _signal_handler)
    while signal_count[0] == 0:
        time.sleep(3600)
    while threading.active_count() > 1:
        time.sleep(1)
    signal.signal(signal.SIGINT, oldint)
    signal.signal(signal.SIGHUP, oldhup)

def create_avahi_group(service, port, text=[]):
    """Register a server with the local Avahi daemon. `service' must be one of
    webdav, http, ftp, ..  Returns the entry group instance from the DBus. Call
    Reset() on it to unregister the group. Will register the instance with atexit
    to make sure it is unregistered."""
    if not has_dbus:
        return False
    bus = dbus.SystemBus()
    dbserver = dbus.Interface(bus.get_object(DBUS_NAME, DBUS_PATH_SERVER), DBUS_INTERFACE_SERVER)
    group = dbus.Interface(bus.get_object(DBUS_NAME, dbserver.EntryGroupNew()), DBUS_INTERFACE_ENTRY_GROUP)
    group.AddService(IF_UNSPEC, PROTO_UNSPEC, dbus.UInt32(0), "megad on " + socket.gethostname(), "_%s._tcp" % service, "", "", dbus.UInt16(port), dbus.Array(text))
    group.Commit()
    logging.getLogger("main").info("Registered %(what)s at port %(port)d with avahi, attributes: %(attributes)s", { "what": "_%s._tcp" % service, "port": port, "attributes": ", ".join(text) or "(none)" })

    atexit.register(group.Reset)
    return group

def iso_time(timestamp):
    "Return an ISO 8601 formatted timestamp."
    return time.strftime("%Y-%m-%dT%H:%M:%S.0Z", time.localtime(timestamp))


def determine_available_cgi_handlers():
    "Return a dictionary of file extensions mapping to available CGI handlers"
    guess = {
        "php": "/usr/bin/php-cgi",
        "pl": "/usr/bin/perl",
        "sh": "/bin/sh",
        "py": "/usr/bin/python",
    }
    for key, value in list(guess.items()):
        if not os.path.exists(value):
            del guess[key]
    return guess

def ucparts(string):
    "Replace foo-bar-baz with Foo-Bar-Baz"
    return "-".join([ "%c%s" % (x[0].upper(), x[1:].lower()) if x else "" for x in string.split("-") ])

def urldecode(string):
    "Replace %xx escape sequences by their byte values"
    return re.sub("%([0-9A-Fa-f]{2})", lambda x: chr(int(x.group(1), 16)), string)

def natsort_key(string):
    "Return a key for natural sorting of a string argument"
    return [ int(s) if s.isdigit() else s for s in re.split(r"\d+", string) ]

def hostportpair(string):
    "Parse a host/port specifier"
    if ":" in string:
        host, port = string.split(":")
        if host in ("*", "a", "all"):
            host = ""
        elif host in ("lo", "l"):
            host = "localhost"
        if port == "":
            port = 1234
        return host, int(port)
    else:
        return "", int(string)


class LogFormatter(logging.Formatter):
    def format(self, record):
        if "ip" in record.args:
            base = "\033[34m[%s %s] \033[35m%s\033[0m " % (self.formatTime(record, "%H:%I:%S"), record.name, record.args["ip"])
        else:
            base = "\033[34m[%s %s] " % (self.formatTime(record, "%H:%I:%S"), record.name)
        if record.levelno > logging.WARNING:
            col = 31
        elif record.levelno > logging.DEBUG:
            col = 32
        else:
            col = 0

        # till 36
        cycle = [ 33, 34, 35, 36, 0 ]
        msg = record.msg
        parts = msg.split()
        for i in range(len(parts)):
            if parts[i][0] == "%":
                parts[i] = "\033[%dm%s\033[0m" % (cycle[0], parts[i])
                cycle = cycle[1:] + [ cycle[0] ]
        msg = " ".join(parts)
        out = msg % record.args
        return "%s\033[%dm%s\033[0m" % (base, col, out)

def main():
    user = False
    password = False

    parser = argparse.ArgumentParser("iwebd", description="Instant web services. Copyright (c) 2015, Phillip Berndt.", epilog="It is required to supply at least one of the server options.", add_help=False)
    parser.add_argument("-f", nargs="?", default=False, type=hostportpair, help="Run ftpd", metavar="port")
    parser.add_argument("-h", nargs="?", default=False, type=hostportpair, help="Run httpd", metavar="port")
    parser.add_argument("-H", nargs="?", default=False, type=hostportpair, help="Run httpsd", metavar="port")
    parser.add_argument("-d", action="store_true", help="Activate webdav in httpd")
    parser.add_argument("-w", action="store_true", help="Activate write access")
    parser.add_argument("-c", action="store_true", help="Allow CGI in httpd")
    parser.add_argument("-a", action="store_true", help="Announce services via Avahi")
    parser.add_argument("-p", help="Only allow authenticated access for user:password", metavar="user:password")
    parser.add_argument("-v", action="store_true", help="Be more verbose")
    parser.add_argument("--ssl-cert", help="Use a custom SSL certificate (Default: Auto-generated)", metavar="file")
    parser.add_argument("--ssl-key", help="Use a custom SSL keyfile (Default: Auto-generated)", metavar="file")
    parser.add_argument("--help", action="help", help="Display this help")
    options = vars(parser.parse_args(sys.argv[1:]))

    if options["f"] is False and options["h"] is False and options["H"] is False:
        parser.print_help()
        parser.exit(0)
    if options["p"]:
        try:
            user, password = options["p"].split(":")
        except:
            parser.error("-p requires an argument of the type `user:password'.")

    logging.basicConfig(level=logging.DEBUG if options["v"] else logging.INFO)

    log_handler = logging.StreamHandler()
    log_handler.setFormatter(LogFormatter())
    logging.getLogger().handlers = []
    logging.getLogger().addHandler(log_handler)
    logger = logging.getLogger("main")

    cgi_handlers = determine_available_cgi_handlers()

    server_options = {
        "write_access": options["w"],
        "dav_enabled": options["d"],
        "user": user,
        "pass": password,
        "allow_cgi": options["c"],
        "cgi_handlers": cgi_handlers,
    }

    if options["H"] is not False:
        if options["ssl_cert"] or options["ssl_key"]:
            assert os.path.isfile(options["ssl_cert"])
            assert os.path.isfile(options["ssl_key"])
            ssl_key = SSLKey(options["ssl_cert"], options["ssl_key"])
        else:
            ssl_key = SSLKey()

    servers = []

    http_variants = []
    if options["h"] is not False:
        http_variants.append(("HTTP", {}, options["h"] or ("", 1234), "http", "webdav"))
    if options["H"] is not False:
        if not has_ssl:
            raise ValueError("No SSL available.")
        http_variants.append(("HTTPS", {"ssl_wrap": ssl_key}, options["H"] or ("", 1234), "https", "webdavs"))

    for name, additional_options, port, avahi_name_http, avahi_name_webdav in http_variants:
        actual_options = server_options.copy()
        actual_options.update(additional_options)
        server, httpd_port = setup_tcp_server(HttpHandler, port, actual_options)
        servers.append(server)
        logger.info("%(what)s server started on %(port)s", {"what": name, "port": ":".join(map(str, httpd_port))})
        if options["a"]:
            create_avahi_group(avahi_name_http, httpd_port)
            if options["d"]:
                user = user or "anonymous"
                create_avahi_group(avahi_name_webdav, httpd_port, [ "u=%s" % user, "path=/" ])

    if options["f"] is not False:
        server, ftpd_port = setup_tcp_server(FtpHandler, options["f"] or ("", 1234), server_options)
        servers.append(server)
        logger.info("%(what)s server started on %(port)s", {"what": "FTP", "port": ":".join(map(str, ftpd_port))})
        if options["a"]:
            create_avahi_group("ftp", ftpd_port)

    wait_for_signal(servers)

if __name__ == '__main__':
    main()

