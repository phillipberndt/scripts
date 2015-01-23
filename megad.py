#!/usr/bin/env python
# encoding: utf-8
#
# Gigantic and monolitic httpd and ftpd and everything else that makes a move from b to c
# Copyright (c) 2015, Phillip Berndt
#
import SocketServer
import StringIO
import atexit
import datetime
import getopt
import grp
import itertools
import logging
import mimetypes
import os
import pwd
import re
import shutil
import signal
import socket
import sys
import threading
import time
import traceback
import urlparse

from wsgiref.handlers import format_date_time

# TODO ngrok support (?!)
# TODO ssl

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

HELP_TEXT = """megad
Copyright (c) 2015, Phillip Berndt

Syntax: megad -<f,h> [other options] [port]

Options:
    -a                  Announce services via Avahi
    -d                  Allow webdav access in httpd
    -f                  Run ftpd
    -h                  Run httpd
    -p "user:password"  Only allow authenticated access
    -v                  Be more verbose
    -w                  Allow write access

"""

class ReusableServer(SocketServer.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, options={}):
        """Constructor.  May be extended, do not override."""
        self.__options = options
        SocketServer.ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass)

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        self.RequestHandlerClass(request, client_address, self, options=self.__options)

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
                self.logger.debug("Data connection from %s for %s accepted" % (remote, self.client_address))
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
        self.logger.debug("Incoming FTP connection from %s" % (str(self.client_address), ))
        self.reply("220 Service ready for new user.")
        while True:
            command = self.rfile.readline().strip()
            if not command:
                break
            self.logger.debug("[%s] Raw command: `%s'" % (self.client_address, command))
            command = command.split(None, 1)

            # Authentication and unauthenticated commands
            if command[0] == "USER":
                if "user" in self.options and command[1] != self.options["user"]:
                    self.reply("430 Invalid username or password")
                elif "pass" in self.options:
                    self.reply("331 User name okay, need password.")
                    self.user = command[1]
                else:
                    self.reply("230 User logged in, proceed.")
                    self.user = command[1]
                    self.logger.info("[%s] %s logged in." % (self.client_address, self.user))
                    self.is_authenticated = True
                continue
            elif command[0] == "PASS" and self.user:
                if "pass" in self.options and command[1] != self.options["pass"]:
                    self.reply("430 Invalid username or password")
                else:
                    self.reply("230 User logged in, proceed.")
                    self.logger.info("[%s] %s logged in." % (self.client_address, self.user))
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

                self.logger.info("[%s] %s %s" % (str(self.client_address), command[0], path))

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
                self.logger.info("[%s] RETR %s" % (str(self.client_address), which_file))
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
                self.logger.info("[%s] %s %s" % (str(self.client_address), command[0], target_file))
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
                    self.logger.info("[%s] Rename %s -> %s" % (str(self.client_address), self.rename_target, target))
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
                    self.logger.info("[%s] %s %s" % (str(self.client_address), command[0], target))
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
                    self.logger.info("[%s] MKDIR %s" % (str(self.client_address), target))
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
                - CGI
                - Compression
                - Digest and Basic authentication
    """
    timeout = 10
    logger  = logging.getLogger("http")

    def __init__(self, request, client_address, server, options={}):
        self.headers = {}
        self.options = options
        self.body_read = False
        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)

    def setup(self):
        SocketServer.StreamRequestHandler.setup(self)
        self.processing_started = time.time()

    def read_http_method(self):
        line = self.rfile.readline()
        if not line:
            return False
        self.method, self.path, self.http_version = line.split()
        if self.http_version.lower() not in ("http/1.1", "http/1.0"):
            raise RuntimeError("Unknown HTTP version %s" % (self.http_version, ))
        return True

    def read_http_headers(self):
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
        self.logger.info("[%s] %s %s %s" % (self.client_address, status.split()[0], self.method, self.path))
        if "Host" not in headers:
            headers["Host"] = self.headers["host"][0] if "host" in self.headers else socket.gethostbyname()
        if "Connection" not in headers:
            headers["Connection"] = self.headers["connection"][0] if "connection" in self.headers else ("Keep-Alive" if self.http_version.lower() == "http/1.1" else "Close")
        self.wfile.write("%s %s\r\n%s\r\n\r\n" % (self.http_version, status, "\r\n".join([
            "%s: %s" % (name, value) for name, value in headers.items()
        ])))

    def send_error(self, error_message, force_close=False, details=""):
        if ("content-length" in self.headers or "transfer-encoding" in self.headers) and not ("expect" in self.headers and "100-continue" in self.headers["expect"]):
            force_close = True
        if force_close:
            self.headers["connection"] = [ "close" ]
        body = "<!DOCTYPE HTML><title>%s</title><body><h1>%s</h1><pre>%s</pre>" % (error_message, error_message, xml_escape(details))
        self.send_header(error_message, { "Content-Length": len(body), "Content-Type": "text/html" })
        self.wfile.write(body)

    def handle_request_for_file(self):
        if os.path.isdir(self.mapped_path):
            mime_type = "text/html"
            data = [ "<!DOCTYPE HTML><title>Directory contents for %(path)s</title><body><h1>Directory contents for %(path)s</h1><ul>" % { "path": xml_escape(self.path) } ]
            base = self.path + ("/" if self.path[-1] != "/" else "")
            data.append("<li><a href='%s'>..</a></li>" % xml_escape(os.path.join(base, "..")))

            dirs = []
            files = []

            for name in os.listdir(self.mapped_path):
                absname = os.path.join(self.mapped_path, name)
                if os.path.isdir(absname):
                    dirs.append("<li><a href='%s'>%s/</a></li>" % (xml_escape(os.path.join(base, name)), xml_escape(name)))
                else:
                    file_mime_type = mimetypes.guess_type(absname)[0] or "application/octet-stream"
                    if has_gtk and gtk.icon_theme_get_default().has_icon(file_mime_type.replace("/", "-")):
                        files.append("<li><img src='/.directory-icons/%s'> <a href='%s'>%s</a></li>" % (file_mime_type.replace("/", "-"), xml_escape(os.path.join(base, name)), xml_escape(name)))
                    else:
                        files.append("<li><a href='%s'>%s</a></li>" % (xml_escape(os.path.join(base, name)), xml_escape(name)))

            data += dirs
            data += files
            data.append("</ul></body>")
            data = "\r\n".join(data)
            size = len(data)
            file = StringIO.StringIO(data)
        else:
            mime_type = mimetypes.guess_type(self.mapped_path)[0]
            stat = os.stat(self.mapped_path)
            size = stat.st_size
            file = open(self.mapped_path, "rb")

        status = "200 Ok"
        self.reply_with_file_like_object(file, size, mime_type, status)

    def reply_with_file_like_object(self, file, size, mime_type, status):
        start = 0
        headers = {}
        if "range" in self.headers:
            req_range_type, req_range = self.headers["range"][0].split("=")
            range_start, range_end = req_range.split("-")
            range_start = int(range_start) if range_start else 0
            range_end = int(range_end) if range_end else (size - 1)
            if req_range_type.lower() != "bytes" or range_start < 0 or range_end < range_start or range_end > size:
                self.send_error("416 Range Not Satisfiable")
                return
            status = "206 Partial Content"
            headers["Content-Range"] = "bytes %d-%d/%d\r\n" % (range_start, range_end, size)
            start = range_start
            size = range_end - range_start + 1

        file.seek(start)

        headers["Content-Length"] = size
        headers["Content-Type"] = mime_type
        headers["Accept-Ranges"] = "bytes"
        self.send_header(status, headers)
        if self.method.lower() != "head":
            fd_copy(file, self.wfile, size)
        file.close()

    def handle_dav_request(self):
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
        url = urlparse.urlparse(url_arg)
        path = re.sub("^/+", "", re.sub("%([0-9A-Fa-f]{2})", lambda x: chr(int(x.group(1)), 16), url.path))
        cwd = os.path.abspath(".")
        mapped_path = os.path.join(cwd, path)
        if mapped_path[:len(cwd)] != cwd:
            return False
        return mapped_path

    def handle_request(self):
        self.body_read = False
        if not self.read_http_method():
            self.rfile.close()
            return
        self.headers = {}
        self.read_http_headers()
        if "host" not in self.headers:
            self.headers["host"] = [ socket.gethostname() ]

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

        self.read_http_body()
        if self.method.lower() not in ("get", "post"):
            self.send_error("405 Method not allowed")
        self.handle_request_for_file()

    def handle(self):
        self.logger.debug("[%s] Accepted connection", self.client_address)
        while not self.rfile.closed:
            try:
                self.handle_request()
            except socket.error:
                break
            except Exception as e:
                self.logger.error("Exception: %s" % "".join(traceback.format_exc()))
                try:
                    self.send_error("500 Internal Server Error", True, details=str(e))
                except socket.error:
                    pass
                break
            if "connection" in self.headers:
                if self.headers["connection"][0].lower() != "keep-alive":
                    break
            elif self.http_version.lower() == "http/1.0":
                break

    def finish(self):
        try:
            SocketServer.StreamRequestHandler.finish(self)
        except:
            pass

def xml_escape(string):
    "Escape special XML/HTML characters"
    return string.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def fd_copy(source_file, target_file, length):
    "Copy length bytes from source_file to target_file"
    buffer = 10240
    if length < 0:
        while True:
            data = source_file.read(buffer)
            if not data:
                break
            if target_file:
                target_file.write(data)
    else:
        while length > 0:
            data = source_file.read(min(buffer, min(length, 10240)))
            if not data:
                raise IOError("Failed to read data")
            if target_file:
                target_file.write(data)
            length -= len(data)

def setup_tcp_server(handler_class, base_port=1234, options={}):
    "Setup a SocketServer on a variable path. Returns the instance and the actual port as a tuple."
    counter = 0
    while True:
        try:
            server = ReusableServer(("", base_port + counter), handler_class, options=options)
            break
        except socket.error:
            counter += 1
            if counter > 100:
                raise
    threading.Thread(target=server.serve_forever).start()
    return server, base_port + counter

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
            sys.exit(0)
        else:
            logging.warn("Second signal received. Killing the process.")
            os.closerange(3, 255)
            os.kill(os.getpid(), signal.SIGKILL)
    oldint = signal.signal(signal.SIGINT, _signal_handler)
    oldhup = signal.signal(signal.SIGHUP, _signal_handler)
    while True:
        time.sleep(3600)
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

    atexit.register(group.Reset)
    return group

def iso_time(timestamp):
    "Return an ISO 8601 formatted timestamp."
    return time.strftime("%Y-%m-%dT%H:%M:%S.0Z", time.localtime(timestamp))

def show_help():
    "Show help text and exit"
    print HELP_TEXT
    sys.exit(0)

def main():
    port = 1234
    user = False
    try:
        (options, arguments) = getopt.getopt(sys.argv[1:], "fhdwdap:")
        if arguments:
            port = int(arguments[0])
        if len(arguments) > 1:
            raise ValueError()
        options = dict(options)
        if "-f" not in options and "-h" not in options:
            raise ValueError()
        if "-p" in options:
            user, password = options["-p"].split(":")
    except:
        show_help()

    logging.basicConfig(level=logging.DEBUG if "-v" in options else logging.INFO)
    logger = logging.getLogger("main")

    server_options = {
        "write_access": "-w" in options,
        "dav_enabled": "-d" in options,
        "user": user,
        "pass": password,
    }

    servers = []

    if "-h" in options:
        server, httpd_port = setup_tcp_server(HttpHandler, port, server_options)
        servers.append(server)
        logger.info("HTTP server started on port %d", httpd_port)
        if "-a" in options:
            create_avahi_group("http", httpd_port)
            if "-d" in options:
                user = user or "anonymous"
                create_avahi_group("webdav", httpd_port, [ "u=%s" % user, "path=/" ])

    if "-f" in options:
        server, ftpd_port = setup_tcp_server(FtpHandler, port, server_options)
        servers.append(server)
        logger.info("FTP server started on port %d", ftpd_port)
        create_avahi_group("ftp", ftpd_port)

    wait_for_signal(servers)

if __name__ == '__main__':
    main()

