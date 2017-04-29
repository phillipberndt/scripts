#!/usr/bin/env python
# encoding: utf-8
#
# Gigantic and monolitic http(s)d and ftpd and everything else that makes a move from b to c
# Copyright (c) 2015, Phillip Berndt
#
from __future__ import print_function, unicode_literals

import sys
IS_PY3 = sys.version_info.major >= 3

if IS_PY3:
    import socketserver as SocketServer
    import io as StringIO
    from io import BytesIO
    import urllib.parse as urlparse
    from functools import reduce
    quote = urlparse.quote
    unqoute = urlparse.unquote
else:
    import SocketServer
    import StringIO
    import urlparse
    import urllib
    BytesIO = StringIO.StringIO
    quote = urllib.quote
    unquote = urllib.unquote

import argparse
import atexit
import base64
import datetime
import email
import email.parser
import errno
import hashlib
import io
import itertools
import json
import locale
import logging
import mimetypes
import os
import re
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import traceback
import urllib
import uuid

from wsgiref.handlers import format_date_time
from functools import partial

# TODO ngrok support (?!)
# TODO htaccess/mod_rewrite support for httpd

try:
    import grp
    import pwd
    has_pwd = True
except ImportError:
    has_pwd = False

try:
    import gtk
    has_gtk = not not gtk.gdk.get_display()
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

try:
    import pyprivbind
    has_pyprivbind = True
except:
    has_pyprivbind = False

try:
    import gzip
    has_gzip = True
except:
    has_gzip = False

try:
    import pyinotify
    has_pyinotify = True
except:
    has_pyinotify = False

try:
    import bz2
    has_bz2 = True
except:
    has_bz2 = False

class SSLKey(object):
    "Tiny container for certificate information that can create self-signed temporary certificates on the fly"
    # TODO maybe add ca: Generate CA like cert below, but then leave the -x509 to create req and sign using `openssl x509 -req -in req -CA foo -CAkey bar -CAcreateserial -out crt`
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
        if not server_address[0]:
            server_address = ("::0" if socket.has_ipv6 else "0.0.0.0", server_address[1])
        if ":" in server_address[0]:
            self.address_family = socket.AF_INET6
        SocketServer.ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass)

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        self.RequestHandlerClass(request, client_address, self, options=self.__options)

    def get_request(self):
        sock, client_address = SocketServer.ThreadingTCPServer.get_request(self)
        if "ssl_wrap" in self.__options:
            sock = ssl.wrap_socket(sock, self.__options["ssl_wrap"].key, self.__options["ssl_wrap"].cert, True, ssl_version = ssl.PROTOCOL_TLSv1 | ssl.PROTOCOL_SSLv23)
        return sock, client_address

    if has_pyprivbind:
        def server_bind(self):
            """Called by constructor to bind the socket.

            May be overridden.

            """
            if self.allow_reuse_address:
                self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                pyprivbind.bind(self.socket, self.server_address)
            except:
                self.socket.bind(self.server_address)
            self.server_address = self.socket.getsockname()

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
            if self.data_mode["mode"] in ("PORT", "EPRT"):
                self.log(logging.DEBUG, "Open socket for %(target)s to %(port)s", target=self.client_address, port=(self.data_mode["ip"], self.data_mode["port"]))
                self.data_mode["socket"] = socket.socket(socket.AF_INET6 if self.data_mode["mode"] == "EPRT" else socket.AF_INET)
                self.data_mode["socket"].connect((self.data_mode["ip"], self.data_mode["port"]))
                self.log(logging.DEBUG, "Opened socket for %(target)s to %(port)s", target=self.client_address, port=(self.data_mode["ip"], self.data_mode["port"]))
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
        if base_path == "//":
            base_path = "/"
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
        self.log(logging.DEBUG, "Client asked for %(path)s, checking for %(what)s %(where)s", path=path, what=expect, where=new_path)
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
            symlink_info = ""
            ftype = "-"
            try:
                fstat = os.lstat(file_path)
                if stat.S_ISLNK(fstat.st_mode):
                    symlink_info = " -> %s" % os.readlink(file_path)
                    ftype = "l"
                elif stat.S_ISDIR(fstat.st_mode):
                    ftype = "d"
            except:
                continue
            mtime = datetime.datetime.fromtimestamp(fstat.st_mtime)
            response.write("%c%c%c%c%c%c%c%c%c%c 1 %s %s %13d %s %3s %s %s%s\r\n" % (
                ftype,
                "r" if fstat.st_mode & 0o0400 else "-",
                "w" if fstat.st_mode & 0o0200 else "-",
                "x" if fstat.st_mode & 0o0100 else "-",
                "r" if fstat.st_mode & 0o0040 else "-",
                "w" if fstat.st_mode & 0o0020 else "-",
                "x" if fstat.st_mode & 0o0010 else "-",
                "r" if fstat.st_mode & 0o0004 else "-",
                "w" if fstat.st_mode & 0o0002 else "-",
                "x" if fstat.st_mode & 0o0001 else "-",
                pwd.getpwuid(fstat.st_uid).pw_name if has_pwd else "-",
                grp.getgrgid(fstat.st_gid).gr_name if has_pwd else "-",
                fstat.st_size,
                mtime.strftime("%b"),
                mtime.strftime("%d"),
                mtime.strftime("%H:%I") if mtime.strftime("%Y") == datetime.datetime.today().strftime("%Y") else mtime.strftime("%Y"),
                element,
                symlink_info))
        response.seek(0)
        return response

    def handle(self):
        self.log(logging.DEBUG, "Incoming FTP connection")
        self.reply("220 Service ready for new user.")
        while True:
            command = self.rfile.readline().strip()
            if not command:
                break
            self.log(logging.DEBUG, "Raw command: `%(command)s'", command=command)
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
            elif command[0] in ("PASV", "PORT", "EPRT", "EPSV"):
                for which in ("socket", "server_socket"):
                    if self.data_mode[which]:
                        self.data_mode[which].shutdown(socket.SHUT_RDWR)
                        self.data_mode[which] = None
                if command[0] in ("PASV", "EPSV"):
                    server_socket, port = setup_tcp_server_socket(1234 if "pasv_port" not in self.options else self.options["pasv_port"],
                            socket.AF_INET6 if command[0] == "EPSV" else socket.AF_INET)
                    server_socket.listen(1)
                    self.data_mode = { "mode": "PASV", "ip": self.request.getsockname()[0], "port": port, "socket": None, "server_socket": server_socket }
                    if command[0] == "PASV":
                        self.reply("227 Entering Passive Mode (%s,%d,%d)." % (self.data_mode["ip"].replace(".", ","), (self.data_mode["port"] & 0xFF00) >> 8, (self.data_mode["port"] & 0x00FF)))
                    else:
                        self.reply("229 Entering Extended Passive Mode (|||%d|)" % self.data_mode["port"])
                else:
                    if command[0] == "PORT":
                        port = command[1].split(",")
                        self.data_mode = { "mode": "PORT", "ip": "%s.%s.%s.%s" % tuple(port[:4]), "port": (int(port[4]) << 8) + int(port[5]), "socket": None, "server_socket": None }
                        self.reply("200 PORT command successful, connecting to %s:%d" % (self.data_mode["ip"], self.data_mode["port"]))
                    else:
                        # EPRT format is EPRT<space><d><net-prt><d><net-addr><d><tcp-port><d>, where d is any character
                        _, _, addr, port, _ = command[1].split(command[1][0])
                        self.data_mode = { "mode": "EPRT", "ip": addr, "port": int(port), "socket": None, "server_socket": None }
                        self.reply("200 EPRT command successful, connecting to %s:%d" % (self.data_mode["ip"], self.data_mode["port"]))

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

                try:
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
                except OSError as e:
                    self.log(logging.WARNING, "Error on accessing %s: %s" % (path, e))
                    self.reply("550 Access denied or not possible")
                    continue
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
                self.reply_with_file(open(which_file, "rb"))
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
                self.reply("350 Requested file action pending further information.")
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

class ChunkWrapper(io.BufferedIOBase):
    "Context-Wrapper around a file-like object that intercepts calls to write() and outputs chunks instead"
    def __init__(self, fileobj):
       self.fileobj = fileobj
       self.finalized = False
       self.offset = 0

    def __enter__(self):
        if hasattr(self.fileobj, "__enter__"):
            self.fileobj.__enter__()
        return self

    def __exit__(self, type, value, traceback):
        if not self.finalized:
            self.fileobj.write(b"0\r\n\r\n")
            self.finalized = True
        if hasattr(self.fileobj, "__exit__"):
            self.fileobj.__exit__(type, value, traceback)

    def write(self, data):
        assert not self.finalized
        if data:
            self.fileobj.write(("%x\r\n" % len(data)).encode() + data + b"\r\n")
            self.offset += len(data)

    def flush(self):
        self.fileobj.flush()

    def truncate(self):
        pass

    def writelines(self, lines):
        for line in lines:
            self.write(line + b"\n")

    def close(self):
        if not self.finalized:
            self.fileobj.write(b"0\r\n\r\n")
            self.fileobj.flush()
            self.finalized = True

    def tell(self):
        return self.offset

if has_gzip:
    class GzipWrapper(gzip.GzipFile):
        "Context-Wrapper around a GzipFile that passes through the underlying file's context wrapper"
        def __enter__(self):
            if hasattr(self.fileobj, "__enter__"):
                self.fileobj.__enter__()
            return self

        def __exit__(self, type, value, traceback):
            fileobj = self.fileobj
            self.flush()
            self.close()
            if hasattr(fileobj, "__exit__"):
                fileobj.__exit__(type, value, traceback)

class EmbedLivereloadWrapper(io.IOBase):
    "Wrapper around a HTML file that embeds a LiveReload JS into the file"
    EMBED_CODE = """<script>document.write('<script src="/.live-reload/lr.js"><' + '/script>');</script>"""

    def __init__(self, fileobj):
        self.fileobj = fileobj
        self.buffer = StringIO.StringIO()
        self._reached_eof = False
        self._fileobj_len = None
        self._injected = False

    def _fill_buffer(self, pos=10240, whence=io.SEEK_CUR):
        if self._reached_eof:
            return
        if whence == io.SEEK_CUR:
            reach = self.buffer.tell() + pos
        elif whence == io.SEEK_SET:
            reach = pos
        elif whence == io.SEEK_END:
            if self._fileobj_len is None:
                pos = self.fileobj.tell()
                self.fileobj.seek(0, io.SEEK_END)
                self._fileobj_len = self.fileobj.tell()
                self.fileobj.seek(pos, io.SEEK_SET)
            reach = self._fileobj_len - pos
        buf_pos = self.buffer.tell()
        remain = reach - len(self.buffer.getvalue())
        if remain > 0:
            while remain > 0:
                data = file_read(self.fileobj, remain)
                self.buffer.write(data)
                if len(data) == 0:
                    self._reached_eof = True
                    break
                remain -= len(data)
            if not self._injected:
                match = re.search("(?i)</body|</html", self.buffer.getvalue())
                inject_at = False
                if match:
                    inject_at = match.start()
                elif self._reached_eof:
                    inject_at = len(self.buffer.getvalue())
                if inject_at is not False:
                    remainder = self.buffer.getvalue()[inject_at:]
                    self.buffer.truncate(inject_at)
                    self.buffer.write(self.EMBED_CODE)
                    self.buffer.write(remainder)
        self.buffer.seek(buf_pos, io.SEEK_SET)

    def close(self):
        self.fileobj.close()

    def tell(self):
        return self.buffer.tell()

    def seek(self, offset, whence=io.SEEK_SET):
        self._fill_buffer(offset, whence)
        self.buffer.seek(offset, whence)

    def read(self, count):
        self._fill_buffer(count)
        return self.buffer.read(count)

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

    SERVER_MESSAGE_PREAMBLE = """<!DOCTYPE HTML><meta charset=utf8><title>%(title)s</title>
        <style>
            body { font-size: 14px; font-family: sans-serif; }
            img { vertical-align: middle; }
            ul { list-style-type: none; }
            a { font-weight: bold; }
        </style>
        <script>
            document.addEventListener("DOMContentLoaded", function() {
                if(document.querySelector("li")) {
                    var ul = document.querySelector("ul");
                    var maxWidth = [ for(l of document.querySelectorAll("li"))
                        [ for (x of l.childNodes) x.offsetWidth ].reduce((x, y) => isNaN(y) ? x : x+y, 0)
                    ].reduce((x, y) => x > y ? x : y, 0)
                    ul.style.columnWidth = ul.style.MozColumnWidth = Math.floor(maxWidth + 15) + "px";
                }
            });
        </script>
        <body>
        <h1>%(title)s</h1>

    """

    POST_FORM_HTML = """
        <form method="post" enctype="multipart/form-data"><h2>Upload</h2><input type=file multiple name=file><input type=submit name=upload value="Upload"></form>
        <div id="upload_progress"><br/></div>
        <script>
            var _xhr_lock = [];
            function xhr_process(action) {
                if(typeof action == "undefined") {
                    _xhr_lock.shift();
                    if(_xhr_lock.length > 0) {
                        _xhr_lock[0]();
                    }
                }
                else {
                    _xhr_lock.push(action);
                    if(_xhr_lock.length == 1) {
                        action();
                    }
                }
            }

            function upload(file) {
                var progress = document.createElement("div");
                progress.innerHTML = "<strong>" + file.name.replace(/</g, "&lt;").replace(/&/g, "&amp;") + "</strong>: <span><progress>0%</progress></span>";
                document.querySelector("#upload_progress").appendChild(progress);

                var xhr = new XMLHttpRequest();
                xhr.open("POST", "", true);
                xhr.onload = function() {
                    progress.querySelector("span").innerHTML = "done";
                    setTimeout(function() {
                        progress.remove();
                    }, 5000);
                    xhr_process();
                };
                xhr.upload.onprogress = function(e) {
                    var percent = 100 * e.loaded / e.total;
                    progress.querySelector("span").innerHTML = "<progress value=" + (percent / 100) + ">" + Math.round(percent, 2) + "%</progress>";
                }
                xhr.onerror = function() {
                    progress.querySelector("span").innerHTML = "failed";
                    xhr_process();
                }
                var data = new FormData();
                data.append("file", file, file.name);
                data.append("upload", "Upload");
                xhr_process(function() {
                    xhr.send(data);
                });
            }

            document.querySelector("form").addEventListener("submit", function(e) {
                e.preventDefault();
                var files = document.querySelector("input[name=file]").files;
                for(var i=0; i<files.length; i++) {
                    upload(files[i]);
                }
            });

            document.querySelector("body").addEventListener("drop", function(e) {
                e.stopPropagation();
                e.preventDefault();
                var files = e.dataTransfer.files;
                for(var i=0; i<files.length; i++) {
                    upload(files[i]);
                }
            });

            document.querySelector("body").addEventListener("dragover", function(e) {
                e.stopPropagation();
                e.preventDefault();
                e.dataTransfer.dropEffect = "copy";
            });
        </script>
    """

    LIVE_RELOAD_JS = """
        window.addEventListener("load", function(e) {
            var urls = [];
            urls.push(document.location.pathname);
            for(var url of performance.getEntries()) {
                if(url.name.substring(0, location.protocol.length + 2 + location.host.length) == location.protocol + "//" + location.host) {
                    urls.push(encodeURIComponent(url.name.substring(location.protocol.length + 2 + location.host.length).replace(/\?.+/, "")));
                }
            }
            var urls_str = urls.join("&");
            var evt = new EventSource("/.live-reload/feed?" + urls_str);
            evt.onmessage = function(msg) {
                for(var url of urls) {
                    if(url.indexOf(msg.data) >= 0) {
                        location.reload();
                        return;
                    }
                }
            }
        }, false);
    """

    DIRECTORY_ICONS = {
        # Taken from Linux Mint / Gnome
        "inode-directory": """
            iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABHNCSVQICAgIfAhkiAAAA8ZJREFU
            WIXtlr1uJEUUhb+qHnuFxROQ8AQLFoFlyYSEsAFC4lEQD0LAS5DxArbkyAQEyAHSCpCQg5UA+Wem
            u+8fQXVX14yXxWYhYq9U011dPXVOnXtuVcObeBP/90ht5+zs7ExVPwRIKZFSGd69zznHarX65ujo
            6LPXJbBqOyJycnJy8iDiFxcXn74u+BaB09PT7wEF9h7yx67r7Pz8PP5KpVeo513Xffv06dNnWwTc
            /b3j42Mi4kHMDw8PV3//1ksjX15efjJ36iQpJa6urv7hnI+LWRGYTPjFV8++M7UP/o3JPZxwJyLK
            /dyAcK/PSPzy9Zfn764AVO39jz/6nP3VE7q8IucVXepIuSOnvEwchrnhruUahpmiLpgJ6iNiI6qC
            2Yho6ZfrgMrAoD0iA89//PkdmFKQUhoIDl5c/wQJUsrklEk5b8kVEXUV7oWMuVZCZqVvNrVpvD5z
            QU1RGxBXqQQgRnc7SLkDgpwyOedCJGcSqYDiRGKStCgSMRNyPAyflHGmfswEdSJoiCimMgBkgCBG
            NSG1+1JTPiQgRQFzI9yXFFTQAlTanCap4MtVEBsxHzeLAuGjmEAqMjtOeOAsJALHbJo4HA9FXXFr
            JVYsDJvHQlCffbKkQExQlb4SiIhepCetDHUhJUg+gScgAicIL6u1MNx8WpGhtqxQJyJuVkBbcFc8
            DBWFxKKAmW42w5r91KE+ApBzYz5KWc35NrNaEYWET8BS8mwyVYZVs7rPc0TxTkrrSkBtXPfjmrz3
            BPGheMGr9QliMl4sZqsrWyrAXWuFuC8Gja0WuAc4DQGX201/y/5bCdERiEn5yQ9RQMMnd7cbjbdV
            MIN7bXU8FhXNDHLcVgIi492mv2G/T/R6V+oCh/lYSNT7okbUyUplzGRsITMrNZPcagbOQuD67vc/
            frt9wd4BiA3lBGMy4NYnQ1DOqmg8MZen16vXvlXAlpC7A3HTlCE3MvaoCWrSEEg78K0ntpUoK132
            /2Vj2r234gG4rgQ87HrQoezhrkB7hi85mE/qcmTvEmiJtCosslcfeODeKOAWaxl6H2XMFjopn5qd
            cflGCGJSgcYHO0pELEZtzDmHaahHUwVh9H0/6tCv952owMsu2KRhkuG+CrHl9FaJ3Y8cU1P3ZiNS
            j0HErB/Har7FhDPw/DOrsF0R7HqC+8CVgLm7smzFpjGO/chm3UMlMOd+N2LLjLM3WiW2NbsfMjom
            NlQC9PHDXerj7ubX8ZX/9Jc/fthXZPN+Dg/x57C9xD3gbaB75HyPDQduAPmPcR4WfwJ2hrgbCtSz
            VQAAAABJRU5ErkJggg==
        """,
        "application-octet-stream": """
            iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAYAAABzenr0AAAABHNCSVQICAgIfAhkiAAAA5pJREFU
            WIXFl81OI0cQgL9uDx7/BCQbgzfriBMHDggph7xSHiIPkBsvkBfIU3DJNYdYnECGi80BO/GY9Q/M
            n7tzWPeopz1jNiyrlDSaqu6a+q/qHqG15v8EzyBCiApQtde+EaRArLVeZwYIIfyrq6ufLy4uftnf
            3//wLbUvFovH6+vrX4UQv2mtIwEI4MNwOPyr3W53DaMQ4l0V26kOgmB8cnLyI/DoARXgY6fT6Sql
            csrfywitNUKIzIhOp9MFPgJ/m3w3tNY5Rlv5Ww2xvTa40QM0wCk423P7eS9wHTMGCEDaEbAN2mWA
            4Tc8RS3trlm0BIQ0ulxGI3g8HrNcLnl4eCBJEtbrNaPR6LMEKZlMJiwWC0ajEWmaMplMWC6XGV3k
            xEaXMFZgR8A1ZL1eI6WkXq8TRRGe5yGlLNwPwzCjG40GYRjmvHZ0SNsAYSu3caUUYRhSrVa/aN+l
            XccsPBeBQjDMSilWqxW+7/P09EQcx8znc+I43tp36dfAdIF0PTN4r9fL5XBvb4+Dg4OMNvvmu16v
            t+WAG/6NvHwKyrx36aI0lK2V1ZWtc6sGXCFJknB7e4tSaosGGA6HBEHAYDAgjuMt/h0G5bugKAIA
            nudRqVSydUOb9krTFM/zaDQaPD8/U61Wc/y2LAeKu6AstGUCtdasVitqtVop/2sR2DlrgyAgiiJm
            sxlxHGe0ea/Xa5RSzOdz6vU60+k020+SZFcEAITpAmFyanshhKDVatFut7O1drudo09PT3Ne+r5P
            q9UqLVo3AsaAfNLY7oJC8wvOif/QBRXYUQPmiaKIfr+fVf1gMGAymdDv9wnDcIuO45h+v18oa1cX
            lILv+7mqTpIkG0aLxWKLrlareJ5XGiEXskmolMpNNDeMBtI0ZT6f02w20Vpv0UA2A4rklB1G2Wlo
            f6y15vHxkZeXl+ytlCJNU4IgoNlsZvR0OqXZbGZ84/GYMAxzA8kZTtKOQA7smX18fEy3m91VOT8/
            z/G6dK1W4+joKJPjTsSyFAjba/uG89qNpwjsVJridSOL1YYC6zQ0ykxNfO2dsOhQ24DEGkQ5ZqPY
            ML/XrbhIngQ0EN7d3X1yme3iectTNow2ukJAVzYG6NlsdnZ2dvb94eGhb1/JpZQ5XEpJpVLJcPtx
            +d0fHCEE9/f3i8vLyz9ubm5+B/4Rm5B/B1wAPwE/vCneXw4PwJ/AtdZ6Kay87PH5b+X1i9zXQQQ8
            a60TgH8Bz9Df3ibzcAYAAAAASUVORK5CYII=
        """
    }

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
        self._body_reader = False
        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)

    def setup(self):
        SocketServer.StreamRequestHandler.setup(self)
        self.processing_started = time.time()

    def read_http_method(self):
        "Read the first line of an HTTP request"
        try:
            line = None
            while not line:
                line = self.rfile.readline().strip().decode()
            self.method, self.path, self.http_version = line.split()
        except:
            self.method = "GET"
            self.path = "/"
            self.request_uri = "/"
            self.http_version = "HTTP/1.1"
            self.send_error("400 Bad request", force_close=True)
            return False
        if self.http_version.lower() not in ("http/1.1", "http/1.0"):
            raise RuntimeError("Unknown HTTP version %s" % (self.http_version, ))
        self.request_uri = self.path
        return True

    def read_http_headers(self):
        r"Read all HTTP headers until \r\n"
        previous_header = None
        while True:
            line = self.rfile.readline().decode()
            line = line[:-2 if len(line) > 1 and line[-2] == "\r" else -1]
            if not line:
                return
            if line[0].isspace():
                self.headers[previous_header][-1] += " %s" % (line.strip(), )
            previous_header, value = line.split(":", 1)
            previous_header = previous_header.lower()
            if previous_header not in self.headers:
                self.headers[previous_header] = []
            self.headers[previous_header].append(value.strip())

    def get_http_body_reader(self):
        "Return a file-like object that reads the body of a request. Returns a singleton for each request."
        if not self._body_reader:
            if "expect" in self.headers and "100-continue" in self.headers["expect"]:
                self.wfile.write(("%s 100 Continue\r\n\r\n" % self.http_version).encode())
            class _body_reader(io.BufferedIOBase):
                def __init__(self, req):
                    self.req = req
                    self.bytes_to_read = int(req.headers["content-length"][0]) if "content-length" in req.headers else None
                    self.chunk_buffer = []
                    self.eof = False
                def read(self, size=None):
                    if self.eof:
                        return ""
                    if self.bytes_to_read is not None:
                        ret = file_read(self.req.rfile, min(self.bytes_to_read, size) if size is not None else self.bytes_to_read)
                        self.bytes_to_read -= len(ret)
                        if not self.bytes_to_read:
                            self.eof = True
                        return ret
                    elif "transfer-encoding" in self.req.headers:
                        if self.req.headers["transfer-encoding"][0] is not "chunked":
                            raise ValueError("Unsupported transfer encoding: %s" % self.req.headers["transfer-encoding"][0])
                        while size is None or size > sum(map(len, self.chunk_buffer)):
                            chunk_size = int(self.rfile.readline(), 16)
                            if chunk_size == 0:
                                self.read_http_headers()
                                self.eof = True
                                break
                            self.chunk_buffer.append(file_read(self.req.rfile, chunk_size))
                        data = "".join(self.chunk_buffer)
                        self.chunk_buffer = [ data[size:] ] if size is not None else []
                        return data[:size] if size is not None else data
                    else:
                        self.eof = True
                        return ""
            self._body_reader = _body_reader(self)
        return self._body_reader

    def read_http_body(self, target_file=None):
        "Read the body of a request. Safe to call twice, as this function memorizes whether the body has been read."
        body_reader = self.get_http_body_reader()
        fd_copy(body_reader, target_file, -1)
        assert body_reader.read() == ""

    def send_header(self, status, headers):
        "Send the headers of a reply."
        if self.path != self.request_uri:
            self.log(logging.INFO, "%(status)s %(method)s %(request_uri)s -> %(path)s", status=status.split()[0], method=self.method, request_uri=self.request_uri, path=self.path)
        else:
            self.log(logging.INFO, "%(status)s %(method)s %(path)s", status=status.split()[0], method=self.method, path=self.path)

        if "Host" not in headers:
            headers["Host"] = self.headers["host"][0] if "host" in self.headers else socket.gethostname()
        if "Connection" not in headers:
            if self.http_version.lower() == "http/1.0":
                if "connection" not in self.headers or self.headers["connection"][0] != "keep-alive":
                    headers["Connection"] = "Close"
                    self.do_keep_alive = False
                else:
                    headers["Connection"] = "Keep-Alive"
            else:
                if "connection" not in self.headers or self.headers["connection"][0] != "close":
                    pass
                else:
                    headers["Connection"] = "Close"
                    self.do_keep_alive = False
        else:
            self.do_keep_alive = headers["Connection"].lower() == "keep-alive"
        headers_list = []
        for name, value in headers.items():
            if type(value) is list:
                for svalue in value:
                    headers_list.append("%s: %s" % (name, svalue))
            else:
                headers_list.append("%s: %s" % (name, value))
        self.wfile.write(("%s %s\r\n%s\r\n\r\n" % (self.http_version, status, "\r\n".join(headers_list))).encode())

    def send_error(self, error_message, force_close=False, details="", headers={}):
        "Reply with an error message. After calling this, you can safely return from any handler."
        if ("content-length" in self.headers or "transfer-encoding" in self.headers) and not ("expect" in self.headers and "100-continue" in self.headers["expect"]):
            force_close = True
        if force_close:
            self.headers["connection"] = [ "close" ]
        body = ("%s%s</body>" % (self.SERVER_MESSAGE_PREAMBLE % { "title": error_message }, xml_escape(details))).encode()
        headers.update({ "Content-Length": len(body), "Content-Type": "text/html" })
        self.send_header(error_message, headers)
        self.wfile.write(body)

    def begin_chunked_reply(self, status, headers):
        assert "Transfer-Encoding" not in headers
        assert "Content-Length" not in headers
        wrapper = [ ChunkWrapper ]
        te_header = [ "chunked" ]
        # A much better way to handle this would be to either react on the
        # TE header being present (which none UA sends, afaik) and then use
        # gzip as a transfer-encoding. Some clients accept the same encodings
        # for transfer-encoding as they do for accept-encoding, so we could simply
        # assume that, but sadly, Firefox is not among them.
        # (Doing so would allow us to use gzip for known content-length's, too)
        if "accept-encoding" in self.headers:
            if has_gzip and "gzip" in ", ".join(self.headers["accept-encoding"]):
                wrapper.append(lambda f: GzipWrapper(mode="w", fileobj=f))
                headers["Content-Encoding"] = [ "gzip" ]
        headers["Transfer-Encoding"] = [ ", ".join(te_header) ]
        self.send_header(status, headers)
        return reduce(lambda x, y: y(x), wrapper, self.wfile if self.method.lower() != "head" else BytesIO())

    def handle_request_for_cgi(self):
        "Like handle_request_for_file, but run the target file as a CGI script"
        file_extension = os.path.splitext(self.mapped_path)[-1][1:]
        if file_extension in self.options["cgi_handlers"]:
            execute = [ self.options["cgi_handlers"][file_extension], self.mapped_path ]
        else:
            execute = [ self.mapped_path ]

        path = urlparse.urlparse(self.path)
        environ = os.environ.copy()
        environ.update({
                "SERVER_SOFTWARE": "ihttpd",
                "SERVER_NAME": self.headers["host"][0] if "host" in self.headers else socket.gethostname(),
                "GATEWAY_INTERFACE": "CGI/1.1",
                "SERVER_PROTOCOL": self.http_version,
                "SERVER_PORT": str(self.request.getsockname()[1]),
                "REQUEST_METHOD": self.method,
                "QUERY_STRING": path.query,
                "SCRIPT_NAME": path.path[:-len(self.path_info)-1] if self.path_info else path.path,
                "PATH_INFO": self.path_info,
                "REQUEST_URI": self.request_uri,
                "PATH_TRANSLATED": os.path.abspath(self.mapped_path),
                "REMOTE_ADDR": self.request.getpeername()[0],
                "CONTENT_TYPE": self.headers["content-type"][0] if "content-type" in self.headers else "",
                "CONTENT_LENGTH": str(self.headers["content-length"][0]) if "content-length" in self.headers else "0",
        })
        for header in self.headers:
            environ["HTTP_%s" % header.upper().replace("-", "_")] = ", ".join(self.headers[header])

        cgi_process = subprocess.Popen(execute, stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True, env=environ, universal_newlines=False)

        def _read_body_to_cgi():
            try:
                self.read_http_body(cgi_process.stdin)
                cgi_process.stdin.close()
            except Exception as e:
                self.send_error("500 Internal server error", True, details=str(e))
        threading.Thread(target=_read_body_to_cgi).start()

        cgi_headers = {}
        last_header = None
        while True:
            cgi_header = cgi_process.stdout.readline().decode()
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
                cgi_headers[last_header][-1] += "\n %s" % cgi_header.strip()
            else:
                last_header, value = cgi_header.split(":", 1)
                last_header = last_header.lower()
                if last_header in cgi_headers:
                    cgi_headers[last_header].append(value.strip())
                else:
                    cgi_headers[last_header] = [ value.strip() ]
        status = "200 Ok" if "status" not in cgi_headers else cgi_headers["status"][0]
        headers = { ucparts(key): value for key, value in cgi_headers.items() if key != "status" }
        if "Content-Type" not in headers:
            headers["Content-Type"] = [ "text/html" ]

        stdout = cgi_process.stdout
        if self.options["live_reload_enabled"] and headers["Content-Type"][0].startswith("text/html"):
            stdout = EmbedLivereloadWrapper(stdout)
            if "content-length" in cgi_headers:
                del cgi_headers["content-length"]
                del headers["Content-Length"]
        if "content-length" in cgi_headers:
            self.send_header(status, headers)
            fd_copy(stdout, self.wfile, int(cgi_headers["content-length"][0]))
        else:
            with self.begin_chunked_reply(status, headers) as wfile:
                fd_copy(stdout, wfile, -1)
        cgi_process.terminate()

    def handle_request_for_file(self):
        "Handle a request for a file, simple GET/HEAD/POST case."
        if os.path.isdir(self.mapped_path):
            request = urlparse.urlparse(self.path)
            query = urlparse.parse_qs(request.query)
            path = request.path

            if "action" in query and query["action"][0] == "download":
                archive_name = os.path.basename(path).replace('"', r'\"') or "download"
                headers = { "Content-Type": "application/x-gtar", "Content-Disposition": "attachment; filename=\"%s.tar%s\"" % (archive_name, ".bz2" if has_bz2 else "") }
                with self.begin_chunked_reply("200 Ok", headers) as wfile:
                    with tarfile.open(mode="w|bz2" if has_bz2 else "w", fileobj=wfile, format=tarfile.GNU_FORMAT) as outfile:
                        outfile.add(self.mapped_path, "")
                return

            if "write_access" in self.options and self.options["write_access"] and "content-type" in self.headers:
                fp = email.parser.FeedParser()
                fp.feed("Content-Type: %s\r\n\r\n" % (self.headers["content-type"][0]))
                body = self.get_http_body_reader()
                while True:
                    data = body.read(1024 ** 2)
                    if not data:
                        break
                    fp.feed(data)
                msg = fp.close()
                del fp
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
                                    data = StringIO.StringIO(part.get_payload())
                                    fd_copy(data, outfile, -1)
                    self.send_header("302 Found", { "Location": path, "Content-Length": 0 })
                    return

            mime_type = "text/html; charset=utf8"
            title = "Directory contents for %s" % xml_escape(os.path.basename(urldecode(path)[:-1]) or "/")
            data = [ self.SERVER_MESSAGE_PREAMBLE % { "title": title }, '<p>Directory: <a href="/">root</a>' ]

            full_dirspec = "/"
            for dirspec in urldecode(path).split("/"):
                if not dirspec:
                    continue
                full_dirspec = "%s%s/" % (full_dirspec, dirspec)
                data.append('&raquo; <a href="%s">%s</a>' % (full_dirspec, dirspec))
            data.append(' (<a href="?action=download">Download as archive</a>)')
            data.append("</p><ul>")

            base = path + ("/" if path[-1] != "/" else "")
            dirs = []
            files = []

            for name in sorted(os.listdir(self.mapped_path), key=natsort_key):
                if name[0] == ".":
                    continue
                absname = os.path.join(self.mapped_path, name)
                if os.path.isdir(absname):
                    dirs.append("<li><img src='/.directory-icons/inode-directory' alt='directory'> <a href='%s/'>%s</a> <em>Folder</em></li>" % (xml_escape(os.path.join(base, name)), xml_escape(name)))
                else:
                    try:
                        file_mime_type = mimetypes.guess_type(absname)[0] or "application/octet-stream"
                        size = format_size(os.stat(absname).st_size)
                    except:
                        size = 0
                        file_mime_type = "application/octet-stream"
                    files.append("<li><img src='/.directory-icons/%s' alt='%s'> <a href='%s'>%s</a> <em>%s</em></li>" % (file_mime_type.replace("/", "-"), file_mime_type, xml_escape(os.path.join(base, name)), xml_escape(name), size))

            data += dirs
            data += files
            data.append("</ul>")
            if "write_access" in self.options and self.options["write_access"]:
                data.append(self.POST_FORM_HTML)
            data.append("</body>")
            data = "\r\n".join(data)
            size = len(data)
            file = BytesIO(data.encode())
        else:
            mime_type = mimetypes.guess_type(self.mapped_path)[0]
            stat = os.stat(self.mapped_path)
            size = stat.st_size
            file = open(self.mapped_path, "rb")
            if self.options["live_reload_enabled"] and mime_type and mime_type.lower() == "text/html":
                file = EmbedLivereloadWrapper(file)
                size = -1

        status = "200 Ok"
        self.read_http_body()
        self.reply_with_file_like_object(file, size, mime_type, status)

    def reply_with_file_like_object(self, file, size, mime_type, status, additional_headers={}):
        "Reply to a request with a file object"
        start = 0
        headers = additional_headers.copy()
        if size >= 0:
            if size > 1024 and size < 1024000 and has_gzip and "accept-encoding" in self.headers and "gzip" in (", ".join(self.headers["accept-encoding"])).lower():
                # Compress small files on the fly
                compressed = BytesIO()
                with gzip.GzipFile(mode="w", fileobj=compressed) as out:
                    file.seek(0)
                    out.write(file.read(size))
                size = compressed.tell()
                compressed.seek(0)
                file = compressed
                headers["Content-Encoding"] = "gzip"
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
        headers["Content-Type"] = mime_type

        if self.method.lower() == "head":
            self.send_header(status, headers)
        elif size < 0:
            with self.begin_chunked_reply(status, headers) as wfile:
                fd_copy(file, wfile, size)
        else:
            self.send_header(status, headers)
            if self.method.lower() != "head":
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
                    response.write("<D:response><D:href>%s%s%s</D:href><D:propstat><D:prop>%s</D:prop><D:status>HTTP/1.1 200 Ok</D:status></D:propstat></D:response>\r\n" % \
                                   (quote(self.path), "/" if self.path[-1] != "/" else "", quote(file_name), res_type))
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
            byte_response = BytesIO(response.getvalue().encode())
            self.reply_with_file_like_object(byte_response, len(byte_response.getvalue()), "text/xml; charset=utf-8", "207 Multi-Status")
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

    def is_path_cgi_candidate(self, mapped_path):
        "Check if a file should be served as a CGI file"
        return "allow_cgi" in self.options and self.options["allow_cgi"] and os.path.isfile(mapped_path) and (os.path.splitext(mapped_path)[-1][1:] in self.options["cgi_handlers"] or os.access(mapped_path, os.X_OK))

    def handle_live_reload(self):
        """Handle a request for live-reload related stuff (js file and websocket protocol)
        """
        if self.path.startswith("/.live-reload/feed"):
            # Home-brew simplified live reload protocol
            urls = None
            if "?" in self.path:
                urls = map(unquote, self.path[self.path.index("?")+1:].split("&"))
                self.log(logging.DEBUG, "Live-reload requested upon change of %(urls)r", urls=urls)
                for url in urls:
                    path = "./%s" % url
                    if os.path.isfile(path):
                        live_reload_add_watch(path)
            else:
                live_reload_add_watch(".", rec=True)
            self.send_header("200 Ok", { "Content-Type": "text/event-stream; charset=UTF-8", "Cache-Control": "no-cache", "Connection": "close" })
            def _handle(event):
                if urls and event.pathname not in urls:
                    return
                try:
                    self.wfile.write("data: %s\n\n" % event.pathname)
                except:
                    pass
            live_reload_register(_handle)
            self.connection.settimeout(3600)
            while True:
                b = self.rfile.read(1024)
                if len(b) < 1024:
                    break
            live_reload_remove(_handle)
            self.send_error("400 Bad request", force_close=True)
        elif self.path == "/.live-reload/lr.js":
            self.reply_with_file_like_object(StringIO.StringIO(self.LIVE_RELOAD_JS), -1, "application/javascript", "200 Ok")
            return
        self.send_error("404 Not found")

    def handle_authentication(self, options_user, options_pass):
        "Return True if the user could be authenticated, or False, in which case the request has already been finished."
        authentication_ok = False
        is_stale = False
        if "authorization" in self.headers:
            method, param = self.headers["authorization"][0].split(None, 1)
            if method.lower() == "basic":
                user, password = base64.b64decode(param).split(":", 1)
                if user == options_user and password == options_pass:
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
                    ha1 = hashlib.md5("%s:%s:%s" % (params["username"], params["realm"], options_pass)).hexdigest()
                    ha2 = hashlib.md5("%s:%s" % (self.method, params["uri"])).hexdigest()
                    response = hashlib.md5("%s:%s:%s:%s:%s:%s" % (ha1, params["nonce"], params["nc"], params["cnonce"], params["qop"], ha2)).hexdigest()
                    self.logger.debug("Digest authentication: Excpected %(expect)s, received %(received)s", {"expect": response, "received": str(params)})
                    if params["nc"] not in data["used_nc"] and response == params["response"] and params["username"] == options_user:
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
            return False
        return True

    def handle_htaccess(self):
        """When self.mapped_path is already set, check for .htaccess files that alter the request.
        Currently, only partial mod_rewrite is available."""
        original_query = "" if "?" not in self.path else self.path[self.path.find("?")+1:]
        path_components = [""] + self.mapped_path.split("/")[len(os.path.abspath(".").split("/")):]
        path_candidate = []
        for part in path_components:
            if part:
                path_candidate.append(part)
            htaccess_file = os.path.join("/".join(path_candidate), ".htaccess")
            if os.path.isfile(htaccess_file):
                partial_request = ("/".join(path_components[len(path_candidate):]))[1:]
                rewrite_engine_status = False
                active_conds = []
                with open(htaccess_file) as hta:
                    for line in hta.readlines():
                        if re.match("\s*RewriteEngine\s+On", line, re.I):
                            rewrite_engine_status = True
                        if rewrite_engine_status:
                            cond_match = re.match("^\s*RewriteCond\s+(?P<test>\S+)\s+(?P<cond>\S+)", line, re.I)
                            if cond_match:
                                active_conds.append(cond_match)
                                continue
                            rule_match = re.match("^\s*RewriteRule\s+(?P<pattern>\S+)\s+(?P<subst>\S+)\s*(?:\[(?P<flags>[^\]+])\])?", line, re.I)
                            if rule_match and re.search(rule_match.group("pattern"), partial_request):
                                cond_failed = False
                                for cond in active_conds:
                                    if "-f" in cond.group("cond") and "request_filename" in cond.group("test").lower():
                                        if os.path.isfile(self.mapped_path) == ("!" in cond.group("cond")):
                                            cond_failed = True
                                    else:
                                        self.log(logging.DEBUG, "Unsupported RewriteCond in %(file)s: %(rule)s", file=htaccess_file, rule=cond.string.strip())
                                active_conds = []
                                if cond_failed:
                                    continue
                                new_partial = re.sub(rule_match.group("pattern"), rule_match.group("subst").replace("$", "\\"), partial_request)
                                new_uri = "/".join(itertools.chain(("",), path_candidate, (new_partial, )))
                                flags = rule_match.group("flags")
                                if flags and "F" in flags:
                                    self.send_error("403 Forbidden")
                                    return False
                                if flags and "G" in flags:
                                    self.send_error("410 Gone")
                                    return False
                                if flags and "R" in flags:
                                    if ":" not in new_uri:
                                        new_uri = "/%s" % new_uri
                                        self.send_error("302 Found", headers={"Location": new_uri})
                                        return False
                                self.path_info = ""
                                if original_query:
                                    new_uri = "%s%s%s" % (new_uri, "?" if "?" not in new_uri else "&", original_query)
                                self.path = new_uri
                                self.mapped_path = self.map_url(new_uri)
                                if not self.mapped_path:
                                    self.send_error("403 Access denied")
                                    return False
                                if flags and "N" in flags:
                                    return self.handle_htaccess()
                                if flags and "L" in flags:
                                    break
        return True

    def handle_request(self):
        "Handle a single request."
        self._body_reader = False
        if not self.read_http_method():
            self.do_keep_alive = False
            return
        self.headers = {}
        self.read_http_headers()
        if "host" not in self.headers:
            self.headers["host"] = [ socket.gethostname() ]

        if "user" in self.options and self.options["user"]:
            # Authenticate the user
            if not self.handle_authentication(self.options["user"], self.options["pass"]):
                return

        if self.path.startswith("/.directory-icons/"):
            load_icon = self.path[18:]
            output = BytesIO()
            def send_data(buf, data=None):
                    output.write(buf)
                    return True
            if has_gtk:
                icon_theme = gtk.icon_theme_get_default()
                if not icon_theme.has_icon(load_icon):
                    load_icon = "application-octet-stream"
                icon_theme.load_icon(load_icon, 32, 0).save_to_callback(send_data, "png", {}, None)
            else:
                output.write(base64.b64decode(self.DIRECTORY_ICONS[load_icon if load_icon in self.DIRECTORY_ICONS else "application-octet-stream"]))
            self.reply_with_file_like_object(output, output.tell(), "image/png", "200 Ok", { "Cache-Control": "public, max-age=31104000" })
            return

        if self.path.startswith("/.live-reload/") and self.options["live_reload_enabled"]:
            self.handle_live_reload()
            return

        self.path_info = ""
        self.mapped_path = self.map_url(self.path[1:])
        if not self.mapped_path:
            self.send_error("403 Access denied")
            return

        if not self.handle_htaccess():
            return

        if "dav_enabled" in self.options and self.options["dav_enabled"] and self.method.upper() in ("PUT", "MKCOL", "DELETE"):
            self.handle_dav_request()
            return

        if not os.path.exists(self.mapped_path):
            if "allow_cgi" in self.options and self.options["allow_cgi"]:
                # This could be a request for /cgi-file/some/path/info
                path_components = self.path[1:].split("/")
                path_candidate = []
                while len(path_components) > 0:
                    path_candidate.append(path_components.pop(0))
                    mapped_candidate = self.map_url("/".join(path_candidate))
                    if os.path.isfile(mapped_candidate) and self.is_path_cgi_candidate(mapped_candidate):
                        self.mapped_path = mapped_candidate
                        self.path_info = "/".join(path_components)
                        if "?" in self.path_info:
                            self.path_info = self.path_info[:self.path_info.index("?")]
                        break
                else:
                    self.send_error("404 Not found")
                    return
            else:
                self.send_error("404 Not found")
                return

        if "dav_enabled" in self.options and self.options["dav_enabled"] and self.method.upper() in ("OPTIONS", "PROPFIND", "MOVE", "COPY"):
            self.handle_dav_request()
            self.read_http_body()
            return

        if self.method.lower() not in ("get", "post", "head"):
            self.send_error("405 Method not allowed")

        if os.path.isdir(self.mapped_path):
            for index_candidate in ("index.html", "index.htm", "index.php"):
                candidate = os.path.join(self.mapped_path, index_candidate)
                if os.path.isfile(candidate):
                    self.mapped_path = candidate

        if self.is_path_cgi_candidate(self.mapped_path):
            self.handle_request_for_cgi()
        else:
            self.handle_request_for_file()

    def handle(self):
        self.log(logging.DEBUG, "Accepted connection")
        while not self.rfile.closed:
            self.do_keep_alive = True
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
            if not self.do_keep_alive:
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
    return string.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")

def format_size(size):
    "Format a human-readable file size"
    prefix = ""
    for prefix in ("", "K", "M", "G", "T"):
        if size < 1024:
            break
        size /= 1024.
    return "%2.2f %sBi" % (size, prefix)

def file_read(fileobj, amount):
    "Safe way to read from file objects that returns '' on non-blocking sockets if no data is available"
    if IS_PY3:
        return fileobj.read(amount)
    if type(fileobj) is not getattr(socket, "_fileobject", False) and hasattr(fileobj, "fileno"):
        try:
            return os.read(fileobj.fileno(), amount)
        except io.UnsupportedOperation:
            return fileobj.read(amount)
    else:
        return fileobj.read(amount)

def file_write(fileobj, data):
    while True:
        try:
            fileobj.write(data)
        except IOError as e:
            if e.errno == errno.EINTR:
                continue
            raise
        break

def fd_copy(source_file, target_file, length):
    "Copy length bytes from source_file to target_file"
    buffer = 10240
    if length < 0:
        while True:
            data = file_read(source_file, buffer)
            if not data:
                break
            if target_file:
                file_write(target_file, data)
    else:
        while length > 0:
            data = file_read(source_file, min(buffer, min(length, 10240)))
            if not data:
                raise IOError("Failed to read data")
            if target_file:
                file_write(target_file, data)
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
    return server, server.socket.getsockname()[:2]

def setup_tcp_server_socket(base_port=1234, address_family=socket.AF_INET):
    "Setup a TCP socket on a variable path. Returns the instance and the actual port as a tuple."
    counter = 0
    while True:
        try:
            server = socket.socket(address_family)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(('', base_port + counter))
            break
        except socket.error:
            counter += 1
            if counter > 100:
                raise
    return server, base_port + counter

def wait_for_signal(servers, extra_thread_count=0, script_file_name=__file__):
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
            if signum == signal.SIGUSR1:
                time.sleep(.5)
                print()
                os.closerange(3, os.sysconf("SC_OPEN_MAX") or 1024)
                os.execv(script_file_name, sys.argv)
                sys.exit(1)
        else:
            logging.warn("Second signal received. Killing the process.")
            os.closerange(3, 255)
            os.kill(os.getpid(), signal.SIGKILL)
    oldint = signal.signal(signal.SIGINT, _signal_handler)
    oldhup = signal.signal(signal.SIGHUP, _signal_handler)
    oldusr = signal.signal(signal.SIGUSR1, _signal_handler)
    while signal_count[0] == 0:
        time.sleep(3600)
    while threading.active_count() > 1 + extra_thread_count:
        print("\r\033[JWaiting for %d remaining conntections to terminate." % (threading.active_count() - 1, ),)
        sys.stdout.flush()
        time.sleep(1)
    signal.signal(signal.SIGINT, oldint)
    signal.signal(signal.SIGHUP, oldhup)
    signal.signal(signal.SIGUSR1, oldusr)

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

def cached_remote_resource(url):
    "Serve a locally cached version of a remote resource"
    cache_dir = os.path.join(os.path.expanduser(os.environ["XDG_CACHE_HOME"] if "XDG_CACHE_HOME" in os.environ else "~/.cache"), "iwebd")
    if not os.path.isdir(cache_dir):
        os.mkdir(cache_dir)
    cache_name = "%s-%s" % (hashlib.sha1(url).hexdigest(), os.path.basename(url))
    cache_file = os.path.join(cache_dir, cache_name)
    if not os.access(cache_file, os.R_OK):
        logger = logging.getLogger("cache")
        logger.info("Loading %(url)s into cache at %(path)s", {"url": url, "path": cache_file})
        urllib.urlretrieve(url, cache_file)
    return open(cache_file)

_live_reload_callbacks = []

def live_reload_register(callback):
    _live_reload_callbacks.append(callback)

def live_reload_remove(callback):
    _live_reload_callbacks.remove(callback)

def live_reload_add_watch(filename, **kwargs):
    global _live_reload_manager
    _live_reload_manager.add_watch(os.path.dirname(filename), pyinotify.IN_CLOSE_WRITE, **kwargs)

def live_reload_setup():
    "Setup inotify for live reload connections"
    global _live_reload_manager
    logger = logging.getLogger("livereload")
    def _handle(event):
        if event.pathname.startswith(os.getcwd()):
            event.pathname = event.pathname[len(os.getcwd()):]
        if os.path.basename(event.pathname).startswith("."):
            # Ignore hidden files
            return
        logger.debug("%(path)s changed, trigger livereload", {"path": event.pathname})
        for cb in _live_reload_callbacks:
            cb(event)
    _live_reload_manager = pyinotify.WatchManager()
    notifier = pyinotify.ThreadedNotifier(_live_reload_manager, _handle)
    notifier.start()

def natsort_key(string):
    "Return a key for natural sorting of a string argument"
    return [ int(s) if s.isdigit() else s for s in re.split(r"(\d+)", string) ]

def hostportpair(service, string):
    "Parse a host/port specifier"
    if ":" in string:
        parts = string.split(":")
        port = parts[-1]
        host = ":".join(parts[:-1])
        if host in ("*", "a", "all"):
            host = ""
        elif host in ("lo", "l"):
            host = "localhost"
        if port == "":
            port = default_port(service)
        return host, int(port)
    else:
        return "", int(string)

class LogFormatter(logging.Formatter):
    def format(self, record):
        if "ip" in record.args:
            base = "\033[34m[%s %s] \033[35m%s\033[0m " % (self.formatTime(record, "%H:%M:%S"), record.name, record.args["ip"])
        else:
            base = "\033[34m[%s %s] " % (self.formatTime(record, "%H:%M:%S"), record.name)
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

def default_port(service):
    if has_pyprivbind:
        return { "httpd": 80, "ftpd": 21, "httpsd": 443 }[service]
    else:
        return 1234

def autoreload(main_pid, watch_file_name):
    logger = logging.getLogger("autoreload")
    def _handle(e):
        logger.info("Reloading due to write to %(self)s", { "self": __file__ })
        while True:
            os.kill(main_pid, signal.SIGUSR1)
            time.sleep(2)
    manager = pyinotify.WatchManager()
    manager.add_watch(watch_file_name, pyinotify.IN_CLOSE_WRITE)
    notifier = pyinotify.Notifier(manager, _handle)
    logger.info("autoreload active")
    notifier.loop()

def main():
    user = False
    password = False

    parser = argparse.ArgumentParser("iwebd", description="Instant web services. Copyright (c) 2015, Phillip Berndt.", epilog="You must supply at least one of the server options.", add_help=False)
    parser.add_argument("-f", nargs="?", default=False, type=partial(hostportpair, "ftpd"), help="Run ftpd", metavar="port")
    parser.add_argument("-h", nargs="?", default=False, type=partial(hostportpair, "httpd"), help="Run httpd", metavar="port")
    if has_ssl:
        parser.add_argument("-H", nargs="?", default=False, type=partial(hostportpair, "httpsd"), help="Run httpsd", metavar="port")
    parser.add_argument("-d", action="store_true", help="Activate webdav in httpd")
    parser.add_argument("-w", action="store_true", help="Activate write access")
    parser.add_argument("-c", action="store_true", help="Allow CGI in httpd")
    if has_dbus:
        parser.add_argument("-a", action="store_true", help="Announce services via Avahi")
    parser.add_argument("-p", help="Only allow authenticated access for user:password", metavar="user:password")
    parser.add_argument("-v", action="store_true", help="Be more verbose")
    if has_ssl:
        parser.add_argument("--ssl-cert", help="Use a custom SSL certificate (Default: Auto-generated)", metavar="file")
        parser.add_argument("--ssl-key", help="Use a custom SSL keyfile (Default: Auto-generated)", metavar="file")
    if has_pyinotify:
        parser.add_argument("--live-reload", action="store_true", help="Activate a live-reload server in httpd (with transparent JS injection)")
    parser.add_argument("--help", action="help", help="Display this help")
    parser.add_argument("--root", help="root directory to serve from", metavar="directory")
    options = vars(parser.parse_args(sys.argv[1:]))

    if options["f"] is False and options["h"] is False and ("H" not in options or options["H"] is False):
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

    locale.setlocale(locale.LC_ALL, "C" if IS_PY3 else b"C")

    cgi_handlers = determine_available_cgi_handlers()

    server_options = {
        "write_access": options["w"],
        "dav_enabled": options["d"],
        "live_reload_enabled": has_pyinotify and options["live_reload"],
        "user": user,
        "pass": password,
        "allow_cgi": options["c"],
        "cgi_handlers": cgi_handlers,
    }

    script_file_name = os.path.abspath(__file__)
    if options["root"]:
        try:
            os.chdir(options["root"])
            logger.info("Serving from %(dir)s", { "dir": os.getcwd() })
        except:
            parser.error("root directory must exist")

    if "H" in options and options["H"] is not False:
        if options["ssl_cert"] or options["ssl_key"]:
            assert os.path.isfile(options["ssl_cert"])
            assert os.path.isfile(options["ssl_key"])
            ssl_key = SSLKey(options["ssl_cert"], options["ssl_key"])
        else:
            ssl_key = SSLKey()

    extra_thread_count = 0

    if server_options["live_reload_enabled"]:
        live_reload_setup()
        extra_thread_count += 1

    servers = []
    http_variants = []
    if options["h"] is not False:
        http_variants.append(("HTTP", {}, options["h"] or ("", default_port("httpd")), "http", "webdav"))
    if "H" in options and options["H"] is not False:
        if not has_ssl:
            raise ValueError("No SSL available.")
        http_variants.append(("HTTPS", {"ssl_wrap": ssl_key}, options["H"] or ("", default_port("httpsd")), "https", "webdavs"))

    for name, additional_options, port, avahi_name_http, avahi_name_webdav in http_variants:
        actual_options = server_options.copy()
        actual_options.update(additional_options)
        server, httpd_port = setup_tcp_server(HttpHandler, port, actual_options)
        servers.append(server)
        logger.info("%(what)s server started on %(port)s", {"what": name, "port": ":".join(map(str, httpd_port))})
        if "a" in options and options["a"]:
            create_avahi_group(avahi_name_http, httpd_port[1])
            if options["d"]:
                user = user or "anonymous"
                create_avahi_group(avahi_name_webdav, httpd_port[1], [ "u=%s" % user, "path=/" ])

    if options["f"] is not False:
        server, ftpd_port = setup_tcp_server(FtpHandler, options["f"] or ("", default_port("ftpd")), server_options)
        servers.append(server)
        logger.info("%(what)s server started on %(port)s", {"what": "FTP", "port": ":".join(map(str, ftpd_port))})
        if "a" in options and options["a"]:
            create_avahi_group("ftp", ftpd_port[1])

    if servers and options["v"]:
        if not has_pyinotify:
            logging.getLogger("autoreload").debug("pyinotify unavailable. Not running autoreload thread.")
        else:
            ar_thread = threading.Thread(target=autoreload, args=(os.getpid(), script_file_name,))
            ar_thread.daemon = True
            ar_thread.start()
            extra_thread_count += 1

    wait_for_signal(servers, extra_thread_count, script_file_name)

if __name__ == '__main__':
    main()

