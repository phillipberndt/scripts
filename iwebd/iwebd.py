#!/usr/bin/env python3
# encoding: utf-8
#
# Gigantic and monolitic http(s)d and ftpd and everything else that makes a move from b to c
# Copyright (c) 2015-2020, Phillip Berndt
#
import socketserver
import io
import argparse
import atexit
import base64
import collections
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
import pty
import re
import select
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
import urllib.request, urllib.parse, urllib.error
import urllib.parse
import uuid
import xml.dom.minidom

from wsgiref.handlers import format_date_time
from functools import partial
from functools import reduce

# TODO (Socks) proxy server
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

try:
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    libc.sendfile.restype = ctypes.c_ssize_t
    libc.sendfile.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_voidp, ctypes.c_size_t)
    libc.strerror.restype = ctypes.c_char_p
    libc.getnameinfo.argtypes = (ctypes.c_voidp, ctypes.c_size_t, ctypes.c_voidp, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_int)
    has_ctypes = True
except:
    libc = None
    has_ctypes = False

class SSLKey(object):
    "Tiny container for certificate information that can create self-signed temporary certificates on the fly"
    def __init__(self, cert=False, key=False):
        if (bool(cert) ^ bool(key)):
            raise ValueError("Either certificate or key not given")
        if cert and key:
            self.cert = cert
            self.key = key
        else:
            self._certfile = tempfile.NamedTemporaryFile(suffix=".crt")
            self._keyfile = tempfile.NamedTemporaryFile(suffix=".key")
            subprocess.call(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost", "-extensions", "usr_cert", "-out", self._certfile.name, "-keyout", self._keyfile.name], stdout=open("/dev/null", "w"), stderr=open("/dev/null", "w"))
            mitmproxy_dir = os.path.expanduser("~/.mitmproxy/")
            if os.path.isdir(mitmproxy_dir) and all(os.path.isfile(os.path.join(mitmproxy_dir, x)) for x in ("mitmproxy-ca-cert.pem", "mitmproxy-ca.pem")):
                temp_cert = self._certfile
                self._certfile = tempfile.NamedTemporaryFile(suffix=".crt")
                subprocess.call(["openssl", "x509", "-set_serial", str(int(time.time())), "-in", temp_cert.name, "-CA", os.path.join(mitmproxy_dir, "mitmproxy-ca-cert.pem"), "-CAkey", os.path.join(mitmproxy_dir, "mitmproxy-ca.pem"), "-out", self._certfile.name], stdout=open("/dev/null", "w"), stderr=open("/dev/null", "w"))
                logging.getLogger("main").info("SSL certificates will be signed with mitmproxy CA from ~/.mitmproxy")
            self.key = self._keyfile.name
            self.cert = self._certfile.name
            logging.getLogger("main").info("SSL certificates created in %s (key) and %s (cert)", self.key, self.cert)

class ReusableServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True

    def __init__(self, server_address, RequestHandlerClass, options={}):
        """Constructor.  May be extended, do not override."""
        self.__options = options
        if not server_address[0]:
            server_address = ("::0" if socket.has_ipv6 else "0.0.0.0", server_address[1])
        if ":" in server_address[0]:
            self.address_family = socket.AF_INET6
        if "ssl_wrap" in self.__options:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=self.__options["ssl_wrap"].cert, keyfile=self.__options["ssl_wrap"].key)
            if options["alpn_protocols"]:
                try:
                    context.set_alpn_protocols(options["alpn_protocols"])
                except:
                    # SSL implementation does not support ALPN
                    pass
            self.ssl_context = context
        socketserver.ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass)

    def finish_request(self, request, client_address):
        """Finish one request by instantiating RequestHandlerClass."""
        self.RequestHandlerClass(request, client_address, self, options=self.__options)

    def get_request(self):
        sock, client_address = socketserver.ThreadingTCPServer.get_request(self)
        if "ssl_wrap" in self.__options:
            sock = self.ssl_context.wrap_socket(sock, server_side=True)
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

class FtpHandler(socketserver.StreamRequestHandler):
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
        socketserver.StreamRequestHandler.__init__(self, request, client_address, server)

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
            self.wfile.write(("%s\r\n" % "\r\n".join(lines)).encode())
        else:
            self.wfile.write(("%s\r\n" % line).encode())

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
                fd_copy(self.data_mode["socket"].makefile("rb"), file, -1)
            else:
                fd_copy(file, self.data_mode["socket"].makefile("wb"), -1)
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
        response = io.StringIO()
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
        response = io.BytesIO(response.read().encode())
        return response

    def handle(self):
        self.log(logging.DEBUG, "Incoming FTP connection")
        self.reply("220 Service ready for new user.")
        while True:
            command = self.rfile.readline().decode().strip()
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
                        response = io.BytesIO()
                        response.write(("\r\n".join(os.listdir(path or "."))).encode())
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
                    target = open(target_file, "wb" if command[0] != "APPE" else "ab")
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
            self.fileobj.write(b"%x\r\n%s\r\n" % (len(data), data))
            self.offset += len(data)

    def flush(self):
        self.fileobj.flush()

    def truncate(self):
        pass

    def writelines(self, lines):
        for line in lines:
            self.write(b"%s\n" % line)

    def close(self):
        if not self.finalized:
            self.fileobj.write(b"0\r\n\r\n")
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
    EMBED_CODE = b"""<script>document.write('<script src="/.well-known/live-reload/lr.js"><' + '/script>');</script>"""

    def __init__(self, fileobj):
        self.fileobj = fileobj
        self.buffer = io.BytesIO()
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
                match = re.search(b"(?i)</body|</html", self.buffer.getvalue())
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

class HttpHandler(socketserver.StreamRequestHandler):
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
            var evt = new EventSource("/.well-known/live-reload/feed?" + urls_str);
            evt.onmessage = function(msg) {
                var cmp = encodeURIComponent(msg.data);
                for(var url of urls) {
                    if(url.indexOf(cmp) >= 0) {
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

    HTTP2_HEADERS_STATIC_TABLE = (
        (b":authority",b""), (b":method",b"GET"), (b":method",b"POST"), (b":path",b"/"), (b":path",b"/index.html"), (b":scheme",b"http"), (b":scheme",b"https"),
        (b":status",b"200"), (b":status",b"204"), (b":status",b"206"), (b":status",b"304"), (b":status",b"400"), (b":status",b"404"), (b":status",b"500"),
        (b"accept-charset",b""), (b"accept-encoding",b"gzip, deflate"), (b"accept-language",b""), (b"accept-ranges",b""), (b"accept",b""), (b"access-control-allow-origin",b""),
        (b"age",b""), (b"allow",b""), (b"authorization",b""), (b"cache-control",b""), (b"content-disposition",b""), (b"content-encoding",b""), (b"content-language",b""),
        (b"content-length",b""), (b"content-location",b""), (b"content-range",b""), (b"content-type",b""), (b"cookie",b""), (b"date",b""), (b"etag",b""), (b"expect",b""),
        (b"expires",b""), (b"from",b""), (b"host",b""), (b"if-match",b""), (b"if-modified-since",b""), (b"if-none-match",b""), (b"if-range",b""), (b"if-unmodified-since",b""),
        (b"last-modified",b""), (b"link",b""), (b"location",b""), (b"max-forwards",b""), (b"proxy-authenticate",b""), (b"proxy-authorization",b""), (b"range",b""),
        (b"referer",b""), (b"refresh",b""), (b"retry-after",b""), (b"server",b""), (b"set-cookie",b""), (b"strict-transport-security",b""), (b"transfer-encoding",b""),
        (b"user-agent",b""), (b"vary",b""), (b"via",b""), (b"www-authenticate",b""),
    )

    HTTP2_HEADERS_HUFFMAN_CODE = (
        (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28), (0xfffffe4, 28), (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28), (0xfffffe8, 28),
        (0xffffea, 24), (0x3ffffffc, 30), (0xfffffe9, 28), (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28), (0xfffffec, 28), (0xfffffed, 28), (0xfffffee, 28),
        (0xfffffef, 28), (0xffffff0, 28), (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28), (0xffffff4, 28), (0xffffff5, 28), (0xffffff6, 28),
        (0xffffff7, 28), (0xffffff8, 28), (0xffffff9, 28), (0xffffffa, 28), (0xffffffb, 28), (0x14, 6), (0x3f8, 10), (0x3f9, 10), (0xffa, 12),
        (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11), (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11), (0xfa, 8), (0x16, 6), (0x17, 6), (0x18, 6), (0x0, 5),
        (0x1, 5), (0x2, 5), (0x19, 6), (0x1a, 6), (0x1b, 6), (0x1c, 6), (0x1d, 6), (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8), (0x7ffc, 15), (0x20, 6), (0xffb, 12),
        (0x3fc, 10), (0x1ffa, 13), (0x21, 6), (0x5d, 7), (0x5e, 7), (0x5f, 7), (0x60, 7), (0x61, 7), (0x62, 7), (0x63, 7), (0x64, 7), (0x65, 7), (0x66, 7),
        (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7), (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7), (0x6f, 7), (0x70, 7), (0x71, 7), (0x72, 7), (0xfc, 8), (0x73, 7),
        (0xfd, 8), (0x1ffb, 13), (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14), (0x22, 6), (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5), (0x24, 6), (0x5, 5),
        (0x25, 6), (0x26, 6), (0x27, 6), (0x6, 5), (0x74, 7), (0x75, 7), (0x28, 6), (0x29, 6), (0x2a, 6), (0x7, 5), (0x2b, 6), (0x76, 7), (0x2c, 6),
        (0x8, 5), (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7), (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15), (0x7fc, 11), (0x3ffd, 14),
        (0x1ffd, 13), (0xffffffc, 28), (0xfffe6, 20), (0x3fffd2, 22), (0xfffe7, 20), (0xfffe8, 20), (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22),
        (0x7fffd9, 23), (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23), (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23),
        (0xffffec, 24), (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24), (0x7fffe1, 23), (0x7fffe2, 23), (0x7fffe3, 23), (0x7fffe4, 23),
        (0x1fffdc, 21), (0x3fffd8, 22), (0x7fffe5, 23), (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24), (0x3fffda, 22), (0x1fffdd, 21),
        (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22), (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21), (0x7fffea, 23), (0x3fffdd, 22), (0x3fffde, 22),
        (0xfffff0, 24), (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23), (0x7fffec, 23), (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
        (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23), (0xfffea, 20), (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23),
        (0x3fffe5, 22), (0x3fffe6, 22), (0x7ffff1, 23), (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20), (0x7fff1, 19), (0x3fffe7, 22), (0x7ffff2, 23),
        (0x3fffe8, 22), (0x1ffffec, 25), (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27), (0x7ffffdf, 27), (0x3ffffe5, 26), (0xfffff1, 24),
        (0x1ffffed, 25), (0x7fff2, 19), (0x1fffe3, 21), (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27), (0xfffff2, 24),
        (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26), (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27), (0xfffec, 20),
        (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21), (0x3fffe9, 22), (0x1fffe7, 21), (0x1fffe8, 21), (0x7ffff3, 23), (0x3fffea, 22), (0x3fffeb, 22),
        (0x1ffffee, 25), (0x1ffffef, 25), (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23), (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26),
        (0x3ffffed, 26), (0x7ffffe7, 27), (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27), (0x7ffffeb, 27), (0xffffffe, 28), (0x7ffffec, 27), (0x7ffffed, 27),
        (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27), (0x3ffffee, 26), (0x3fffffff, 30),
    )


    def log(self, lvl, msg, *args, **kwargs):
        kwargs.update({
            "ip": self.client_address[0],
        })
        if "status" in kwargs:
            if kwargs["status"].startswith("2") or kwargs["status"].startswith("3"):
                kwargs["status"] += " \033[1;32m✓"
            else:
                kwargs["status"] += " \033[1;31m✗"
        self.logger.log(lvl, msg, kwargs)

    def __init__(self, request, client_address, server, options={}, use_gzip=has_gzip):
        self.use_gzip = use_gzip
        self.headers = {}
        self.http_version = "HTTP/1.1"
        self.options = options
        if not "_http_active_nonces" in options:
            options["_http_active_nonces"] = {}
        self.active_nonces = options["_http_active_nonces"]
        self._body_reader = False
        socketserver.StreamRequestHandler.__init__(self, request, client_address, server)

    def setup(self):
        socketserver.StreamRequestHandler.setup(self)
        self.processing_started = time.time()

    def read_http_method(self):
        "Read the first line of an HTTP request"
        try:
            line = None
            while not line:
                try:
                    line = self.rfile.readline().decode()
                except IOError as e:
                    if e.errno == errno.EAGAIN:
                        continue
                    raise
                if not line:
                    raise socket.error()
                line = line.strip()
            self.method, self.path, self.http_version = line.split()
        except socket.error:
            raise
        except:
            self.method = "GET"
            self.path = "/"
            self.request_uri = "/"
            self.http_version = "HTTP/1.1"
            self.send_error("400 Bad request", force_close=True, details=traceback.format_exc())
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
                break
            if line[0].isspace():
                self.headers[previous_header][-1] += " %s" % (line.strip(), )
            previous_header, value = line.split(":", 1)
            previous_header = previous_header.lower()
            if previous_header not in self.headers:
                self.headers[previous_header] = []
            self.headers[previous_header].append(value.strip())
        self.do_keep_alive = "connection" not in self.headers or self.headers["connection"][0].lower() != "close"

    def get_http_body_reader(self):
        "Return a file-like object that reads the body of a request. Returns a singleton for each request."
        if not self._body_reader:
            if "expect" in self.headers and "100-continue" in self.headers["expect"]:
                self.wfile.write("%s 100 Continue\r\n\r\n" % self.http_version)
            class _body_reader(io.BufferedIOBase):
                def __init__(self, req):
                    self.req = req
                    self.bytes_to_read = int(req.headers["content-length"][0]) if "content-length" in req.headers else None
                    self.chunk_buffer = []
                    self.eof = False
                def read(self, size=None):
                    if self.eof:
                        return b""
                    if self.bytes_to_read is not None:
                        ret = file_read(self.req.rfile, min(self.bytes_to_read, size) if size is not None else self.bytes_to_read)
                        self.bytes_to_read -= len(ret)
                        if not self.bytes_to_read:
                            self.eof = True
                        return ret
                    elif "transfer-encoding" in self.req.headers:
                        if self.req.headers["transfer-encoding"][0] != "chunked":
                            raise ValueError("Unsupported transfer encoding: %s" % self.req.headers["transfer-encoding"][0])
                        while size is None or size > sum(map(len, self.chunk_buffer)):
                            chunk_size = int(self.rfile.readline(), 16)
                            if chunk_size == 0:
                                self.read_http_headers()
                                self.eof = True
                                break
                            self.chunk_buffer.append(file_read(self.req.rfile, chunk_size))
                        data = b"".join(self.chunk_buffer)
                        self.chunk_buffer = [ data[size:] ] if size is not None else []
                        return data[:size] if size is not None else data
                    else:
                        self.eof = True
                        return b""
            self._body_reader = _body_reader(self)
        return self._body_reader

    def read_http_body(self, target_file=None):
        "Read the body of a request. Safe to call twice, as this function memorizes whether the body has been read."
        body_reader = self.get_http_body_reader()
        fd_copy(body_reader, target_file, -1)
        assert body_reader.read() == b""

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
                    headers["Connection"] = "Keep-Alive"
                    self.do_keep_alive = True
                else:
                    headers["Connection"] = "Close"
                    self.do_keep_alive = False
        else:
            self.do_keep_alive = headers["Connection"].lower() == "keep-alive"
        headers_list = []
        for name, value in list(headers.items()):
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
        body = "%s%s</body>" % (self.SERVER_MESSAGE_PREAMBLE % { "title": error_message }, xml_escape(details))
        headers.update({ "Content-Length": len(body), "Content-Type": "text/html" })
        self.send_header(error_message, headers)
        self.wfile.write(body.encode())

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
            if self.use_gzip and "gzip" in ", ".join(self.headers["accept-encoding"]):
                wrapper.append(lambda f: GzipWrapper(mode="w", fileobj=f))
                headers["Content-Encoding"] = [ "gzip" ]
        headers["Transfer-Encoding"] = [ ", ".join(te_header) ]
        self.send_header(status, headers)
        return reduce(lambda x, y: y(x), wrapper, self.wfile if self.method.lower() != "head" else io.BytesIO())

    def handle_request_for_cgi(self):
        "Like handle_request_for_file, but run the target file as a CGI script"
        file_extension = os.path.splitext(self.mapped_path)[-1][1:]
        if file_extension in self.options["cgi_handlers"]:
            execute = [ self.options["cgi_handlers"][file_extension], self.mapped_path ]
        else:
            execute = [ self.mapped_path ]

        path = urllib.parse.urlparse(self.path)
        environ = os.environ.copy()
        environ.update({
                "SERVER_SOFTWARE": "ihttpd",
                "SERVER_NAME": self.headers["host"][0] if "host" in self.headers else socket.gethostname(),
                "GATEWAY_INTERFACE": "CGI/1.1",
                "SERVER_PROTOCOL": self.http_version,
                "SERVER_PORT": str(self.server.socket.getsockname()[1]),
                "REQUEST_METHOD": self.method,
                "QUERY_STRING": path.query,
                "SCRIPT_NAME": path.path[:-len(self.path_info)-1] if self.path_info else path.path,
                "PATH_INFO": self.path_info,
                "REQUEST_URI": self.request_uri,
                "PATH_TRANSLATED": os.path.abspath(self.mapped_path),
                "REMOTE_ADDR": self.client_address[0],
                "CONTENT_TYPE": self.headers["content-type"][0] if "content-type" in self.headers else "",
                "CONTENT_LENGTH": str(self.headers["content-length"][0]) if "content-length" in self.headers else "0",
                "REDIRECT_STATUS": "200",
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
                if ":" not in cgi_header:
                    self.send_error("500 Internal server error", True, "Unexpected CGI header: %s" % cgi_header)
                    cgi_process.terminate()
                    return
                last_header, value = cgi_header.split(":", 1)
                last_header = last_header.lower()
                if last_header in cgi_headers:
                    cgi_headers[last_header].append(value.strip())
                else:
                    cgi_headers[last_header] = [ value.strip() ]

        status = "200 Ok" if "status" not in cgi_headers else cgi_headers["status"][0]
        headers = { ucparts(key): value for key, value in list(cgi_headers.items()) if key != "status" }
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
        elif not self.do_keep_alive:
            self.send_header("200 Ok", headers)
            fd_copy(stdout, self.wfile, -1)
        else:
            with self.begin_chunked_reply(status, headers) as wfile:
                fd_copy(stdout, wfile, -1)
        cgi_process.terminate()

    def handle_request_for_file(self):
        "Handle a request for a file, simple GET/HEAD/POST case."
        if os.path.isdir(self.mapped_path):
            request = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(request.query)
            path = request.path

            if "action" in query and query["action"][0] == "download":
                archive_name = os.path.basename(path).replace('"', r'\"') or "download"
                headers = { "Content-Type": "application/x-gtar", "Content-Disposition": "attachment; filename=\"%s.tar%s\"" % (archive_name, ".bz2" if has_bz2 else "") }
                if self.do_keep_alive:
                    with self.begin_chunked_reply("200 Ok", headers) as wfile:
                        outfile = tarfile.open(mode="w|bz2" if has_bz2 else "w", fileobj=wfile, format=tarfile.GNU_FORMAT)
                        outfile.add(self.mapped_path)
                        outfile.close()
                else:
                    self.send_header("200 Ok", headers)
                    self.connection.setblocking(True) # Workaround for http/2 support
                    outfile = tarfile.open(mode="w|bz2" if has_bz2 else "w", fileobj=self.wfile, format=tarfile.GNU_FORMAT)
                    outfile.add(self.mapped_path)
                    outfile.close()
                return

            if "write_access" in self.options and self.options["write_access"] and "content-type" in self.headers:
                # TODO Cannot use this in Python3
                fp = email.parser.BytesFeedParser()
                fp.feed(("Content-Type: %s\r\n\r\n" % (self.headers["content-type"][0])).encode())
                body = self.get_http_body_reader()
                while True:
                    data = body.read(1024 ** 2)
                    fp.feed(data)
                    if not data:
                        break
                msg = fp.close()
                del fp
                is_upload = False
                for part in msg.get_payload():
                    # A simple hack to work around that multipart/form-data does not escape file names in headers
                    for i in range(len(part._headers)):
                        part._headers[i] = (part._headers[i][0], part._headers[i][1].encode("ascii", "surrogateescape").decode())
                    if "upload" in str(part.get("Content-Disposition", "")) and part.get_payload() == "Upload":
                        is_upload = True
                        break
                if is_upload:
                    for part in msg.get_payload():
                        disposition = str(part.get("content-disposition", ""))
                        filename = re.search(r'filename="((?:[^"]|\")+)"', disposition)
                        cte = part.get("content-transfer-encoding", "")
                        if filename:
                            filename = filename.group(1).replace(r'\"', '"')
                            self.logger.info("Received file %(filename)s", { "filename": filename })
                            if not "/" in filename:
                                with open(os.path.join(self.mapped_path, filename), "wb") as outfile:
                                    data = io.BytesIO(part.get_payload(decode=True) if cte else part._payload.encode("ascii", "surrogateescape"))
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
                    dirs.append("<li><img src='/.well-known/directory-icons/inode-directory' alt='directory'> <a href='%s/'>%s</a> <em>Folder</em></li>" % (xml_escape(os.path.join(base, name)), xml_escape(name)))
                else:
                    try:
                        file_mime_type = mimetypes.guess_type(absname)[0] or "application/octet-stream"
                        size = format_size(os.stat(absname).st_size)
                    except:
                        size = 0
                        file_mime_type = "application/octet-stream"
                    files.append("<li><img src='/.well-known/directory-icons/%s' alt='%s'> <a href='%s'>%s</a> <em>%s</em></li>" % (file_mime_type.replace("/", "-"), file_mime_type, xml_escape(os.path.join(base, name)), xml_escape(name), size))

            data += dirs
            data += files
            data.append("</ul>")
            if "write_access" in self.options and self.options["write_access"]:
                data.append(self.POST_FORM_HTML)
            data.append("</body>")
            data = "\r\n".join(data)
            data = data.encode()
            size = len(data)
            file = io.BytesIO(data)
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
            if size > 1024 and size < 102400 and self.use_gzip and "accept-encoding" in self.headers and "gzip" in (", ".join(self.headers["accept-encoding"])).lower():
                # Compress small files on the fly
                compressed = io.BytesIO()
                out = GzipWrapper(mode="wb", fileobj=compressed)
                file.seek(0)
                out.write(file.read(size))
                out.flush()
                size = compressed.tell()
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
        elif size < 0 and self.do_keep_alive:
            with self.begin_chunked_reply(status, headers) as wfile:
                fd_copy(file, wfile, size)
        else:
            self.send_header(status, headers)
            if self.method.lower() != "head":
                fd_copy(file, self.wfile, size)
        file.close()

    def handle_dav_request(self):
        "Handle webdav specific methods."
        # TODO Webdav does not work yet
        method = self.method.upper()
        if method == "OPTIONS":
            self.read_http_body()
            self.send_header("200 Ok", {
                "Allow": "OPTIONS, GET, HEAD, POST, PUT, DELETE, COPY, MOVE, MKCOL, PROPFIND" if "write_access" in self.options and self.options["write_access"] else "OPTIONS, GET, HEAD, POST, PUT, PROPFIND",
                "DAV": "1, 2, ordered-collections",
                "Content-Length": 0 })
        elif method == "PROPFIND":
            self.read_http_body()
            response = io.StringIO()
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
                                   (urllib.parse.quote(self.path), "/" if self.path[-1] != "/" else "", urllib.parse.quote(file_name), res_type))
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
            response = io.BytesIO(response.read().encode())
            self.reply_with_file_like_object(response, len(response.getbuffer()), "text/xml; charset=utf-8", "207 Multi-Status")
        elif not "write_access" in self.options or not self.options["write_access"]:
            self.read_http_body()
            self.send_error("405 Method not allowed")
        elif method == "PUT":
            try:
                target_file = open(self.mapped_path, "wb")
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
        url = urllib.parse.urlparse(url_arg)
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

    def handle_dlna(self):
        """Handle a request for dlna related stuff"""
        if self.path.startswith("/.well-known/dlna/description.xml"):
            self.reply_with_file_like_object(io.BytesIO("""<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion>
                <device><deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType><friendlyName>iwebd on {host}</friendlyName><serialNumber>1</serialNumber>
                <UDN>uuid:2f71654a-4ed0-486d-96a8-5185f96dea1e</UDN><serviceList>
                <service><serviceType>urn:schemas-upnp-org:service:ContentDirectory:1</serviceType><serviceId>urn:upnp-org:serviceId:ContentDirectory</serviceId><SCPDURL>/.well-known/dlna/cds.xml</SCPDURL>
                <controlURL>/.well-known/dlna/control/cds</controlURL><eventSubURL>/.well-known/dlna/event/cds</eventSubURL></service>
                </serviceList></device><URLBase>http://{host}/</URLBase></root>""".format(host=self.headers["host"][0]).encode()), -1, "application/xml; charset=utf8", "200 Ok")
            return

        if self.path.startswith("/.well-known/dlna/cds.xml"):
            self.reply_with_file_like_object(io.BytesIO(b"""<?xml version="1.0" encoding="utf-8"?><scpd xmlns="urn:schemas-upnp-org:service-1-0">
                    <specVersion> <major>1</major> <minor>0</minor> </specVersion> <actionList> <action> <name>Browse</name> <argumentList> <argument> <name>ObjectID</name> <direction>in</direction>
                    <relatedStateVariable>A_ARG_TYPE_ObjectID</relatedStateVariable> </argument> <argument> <name>BrowseFlag</name> <direction>in</direction> <relatedStateVariable>A_ARG_TYPE_BrowseFlag</relatedStateVariable>
                    </argument> <argument> <name>Filter</name> <direction>in</direction> <relatedStateVariable>A_ARG_TYPE_Filter</relatedStateVariable> </argument> <argument> <name>StartingIndex</name> <direction>in</direction>
                    <relatedStateVariable>A_ARG_TYPE_Index</relatedStateVariable> </argument> <argument> <name>RequestedCount</name> <direction>in</direction> <relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable> </argument>
                    <argument> <name>SortCriteria</name> <direction>in</direction> <relatedStateVariable>A_ARG_TYPE_SortCriteria</relatedStateVariable> </argument> <argument> <name>Result</name> <direction>out</direction>
                    <relatedStateVariable>A_ARG_TYPE_Result</relatedStateVariable> </argument> <argument> <name>NumberReturned</name> <direction>out</direction> <relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable> </argument>
                    <argument> <name>TotalMatches</name> <direction>out</direction> <relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable> </argument> <argument> <name>UpdateID</name> <direction>out</direction>
                    <relatedStateVariable>A_ARG_TYPE_UpdateID</relatedStateVariable> </argument> </argumentList> </action> <action> <name>GetSearchCapabilities</name> <argumentList> <argument> <name>SearchCaps</name> <direction>out</direction>
                    <relatedStateVariable>SearchCapabilities</relatedStateVariable> </argument> </argumentList> </action> <action> <name>GetSortCapabilities</name> <argumentList> <argument> <name>SortCaps</name>
                    <direction>out</direction> <relatedStateVariable>SortCapabilities</relatedStateVariable> </argument> </argumentList> </action> <action> <name>GetSystemUpdateID</name> <argumentList> <argument> <name>Id</name>
                    <direction>out</direction> <relatedStateVariable>SystemUpdateID</relatedStateVariable> </argument> </argumentList> </action> </actionList> <serviceStateTable> <stateVariable sendEvents="no"> <name>A_ARG_TYPE_BrowseFlag</name>
                    <dataType>string</dataType> <allowedValueList> <allowedValue>BrowseMetadata</allowedValue> <allowedValue>BrowseDirectChildren</allowedValue> </allowedValueList> </stateVariable> <stateVariable sendEvents="yes">
                    <name>SystemUpdateID</name> <dataType>ui4</dataType> </stateVariable> <stateVariable sendEvents="yes"> <name>ContainerUpdateIDs</name> <dataType>string</dataType> </stateVariable> <stateVariable sendEvents="no">
                    <name>A_ARG_TYPE_Count</name> <dataType>ui4</dataType> </stateVariable> <stateVariable sendEvents="no"> <name>A_ARG_TYPE_SortCriteria</name> <dataType>string</dataType> </stateVariable> <stateVariable sendEvents="no">
                    <name>SortCapabilities</name> <dataType>string</dataType> </stateVariable> <stateVariable sendEvents="no"> <name>A_ARG_TYPE_Index</name> <dataType>ui4</dataType> </stateVariable> <stateVariable sendEvents="no">
                    <name>A_ARG_TYPE_ObjectID</name> <dataType>string</dataType> </stateVariable> <stateVariable sendEvents="no"> <name>A_ARG_TYPE_UpdateID</name> <dataType>ui4</dataType> </stateVariable> <stateVariable sendEvents="no">
                    <name>A_ARG_TYPE_Result</name> <dataType>string</dataType> </stateVariable> <stateVariable sendEvents="no"> <name>SearchCapabilities</name> <dataType>string</dataType> </stateVariable> <stateVariable sendEvents="no">
                    <name>A_ARG_TYPE_Filter</name> <dataType>string</dataType> </stateVariable> </serviceStateTable> </scpd> """), -1, "application/xml; charset=utf8", "200 Ok")
            return

        if self.path.startswith("/.well-known/dlna/event/cds"):
            self.send_error("200 Ok", True, "", {"Sid": "uuid:0bec14cb-4850-483c-b18a-6da73a4add75"})
            return

        if self.path.startswith("/.well-known/dlna/control/cds"):
            if "soapaction" not in self.headers or "urn:schemas-upnp-org:service:ContentDirectory:1#Browse" not in self.headers["soapaction"][0]:
                self.send_error("404 Not Found")
                return
            body = self.get_http_body_reader().read().decode()
            request = xml.dom.minidom.parseString(body)
            assert request.documentElement.firstChild.firstChild.nodeName.lower().endswith("browse")
            request_attrs = {}
            for child in request.documentElement.firstChild.firstChild.childNodes:
                name = child.nodeName
                if ":" in name:
                    name = name[name.find(":")+1:]
                request_attrs[name] = "".join([ x.toxml() for x in child.childNodes ])

            self.log(logging.DEBUG, "DLNA request with request attrs: %(attrs)r", attrs=request_attrs)
            object_id = int(request_attrs.get("ObjectID"))

            if not hasattr(HttpHandler, "_dlna_objects"):
                HttpHandler._dlna_objects = { 0: (-1, ".") }
                HttpHandler._dlna_inverse = { ".": 0 }
                HttpHandler._dlna_maxkey = 0

            result_elements = []
            if object_id in HttpHandler._dlna_objects:
                parent, base_path = HttpHandler._dlna_objects[object_id]
                if os.path.isfile(base_path):
                    object_id = parent
                    parent, base_path = HttpHandler._dlna_objects[object_id]

                if request_attrs.get("BrowseFlag", "BrowseMetadata") == "BrowseMetadata":
                    contents = [""]
                else:
                    contents = os.listdir(base_path)

                for fn in contents:
                    path = os.path.join(base_path, fn)
                    if os.path.isdir(path):
                        path += "/"

                    if path not in HttpHandler._dlna_inverse:
                        HttpHandler._dlna_maxkey += 1
                        key = HttpHandler._dlna_maxkey
                        HttpHandler._dlna_inverse[path] = key
                        HttpHandler._dlna_objects[key] = (object_id, path)
                    else:
                        key = HttpHandler._dlna_inverse[path]

                    try:
                        if os.path.isdir(path):
                                child_count = len(os.listdir(path))
                                result_elements.append(xml_escape('<container id="{}" parentID="{}" restricted="false" childCount="{}"><dc:title>{}</dc:title><upnp:class>object.container.storageFolder</upnp:class></container>'.format(
                                    key, object_id, child_count, xml_escape(fn))))
                        else:
                            file_mime_type = mimetypes.guess_type(path)[0] or "application/octet-stream"
                            result_elements.append(xml_escape('<item id="{}" parentID="{}" restricted="false"><dc:title>{}</dc:title><upnp:class>object.item.{}Item</upnp:class><res protocolInfo="http-get:*:{}:*" size="{}">http://{}/{}</res></item>'.format(
                                key, object_id, xml_escape(fn), file_mime_type.split("/")[0], file_mime_type, os.stat(path).st_size, xml_escape(self.headers["host"][0]), xml_escape(urllib.parse.quote(path)))))
                    except OSError:
                        pass


            count = int(request_attrs.get("RequestedCount", "99999")) or 9999
            start = int(request_attrs.get("StartingIndex", 0))
            filtered_results = result_elements[start:start+count]

            result = ['<?xml version="1.0" encoding="utf-8" standalone="yes"?>',
                      '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body><u:BrowseResponse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1"><Result>']
            result.append(xml_escape('<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/">'))
            result += filtered_results

            result.append(xml_escape('</DIDL-Lite>'))
            result.append('</Result><NumberReturned>{}</NumberReturned><TotalMatches>{}</TotalMatches><UpdateID>0</UpdateID></u:BrowseResponse></s:Body></s:Envelope>'.format(len(filtered_results), len(result_elements)))
            out = "".join(result)
            out = out.encode()

            self.reply_with_file_like_object(io.BytesIO(out), len(out), "text/xml; charset=UTF-8", "200 OK", {"Ext": "", "Connection": "close", "Server": "Linux/4.10.0-40-generic, UPnP/1.0, MediaTomb/0.12.2"})
            return

        self.send_error("404 Not Found")
        return

    def handle_live_reload(self):
        """Handle a request for live-reload related stuff (js file and websocket protocol)"""
        if self.path.startswith("/.well-known/live-reload/feed"):
            # Home-brew simplified live reload protocol
            urls = None
            if "?" in self.path:
                urls = list(map(urllib.parse.unquote, self.path[self.path.index("?")+1:].split("&")))
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
                    self.wfile.write(b"data: %s\n\n" % event.pathname.encode())
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
        elif self.path == "/.well-known/live-reload/lr.js":
            self.reply_with_file_like_object(io.BytesIO(self.LIVE_RELOAD_JS.encode()), -1, "application/javascript", "200 Ok")
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
        self.request_uri = None
        self.path = None
        self._body_reader = False
        if not self.read_http_method():
            raise socket.error()
        self.headers = {}
        self.read_http_headers()
        if "host" not in self.headers:
            self.headers["host"] = [ socket.gethostname() ]

        if "user" in self.options and self.options["user"]:
            # Authenticate the user
            if not self.handle_authentication(self.options["user"], self.options["pass"]):
                return

        if self.path.startswith("/.well-known/directory-icons/"):
            load_icon = self.path[18:]
            output = io.BytesIO()
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
            size = output.tell()
            output.seek(0)
            self.reply_with_file_like_object(output, size, "image/png", "200 Ok", { "Cache-Control": "public, max-age=31104000" })
            return

        if self.path.startswith("/.well-known/live-reload/") and self.options["live_reload_enabled"]:
            self.handle_live_reload()
            return

        if self.path.startswith("/.well-known/dlna/") and self.options["dlna"]:
            self.handle_dlna()
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

    # http/2 implementation: {{{
    def hpack_decode(self, data):
        if not hasattr(self, "_http2_dynamic_header_table"):
            self._http2_dynamic_header_table = []
        headers = []

        data = list(data)

        def _consume_int(prefix):
            prefix_bits = (1<<prefix) - 1
            if data[0] & prefix_bits == prefix_bits:
                output = prefix_bits
                data.pop(0)
                bit_pos = 0
                while data[0] >= 128:
                    output += (data[0] & 127) << bit_pos
                    bit_pos += 7
                    data.pop(0)
                output += (data[0] << bit_pos)
                data.pop(0)
            else:
                output = data[0] & prefix_bits
                data.pop(0)
            return output

        def _consume_str():
            is_huffmann = data[0] & 128
            str_len = _consume_int(7)
            str_data = data[:str_len]
            for i in range(str_len):
                data.pop(0)
            if not is_huffmann:
                return b"".join(str_data)
            prefix = 8
            output = []
            while str_data:
                full_width_word_from_current = ((str_data[0] & ((1 << prefix) - 1)) << (32 - prefix)) + \
                        ((str_data[1] if len(str_data) > 1 else 0) << (24 - prefix)) + \
                        ((str_data[2] if len(str_data) > 2 else 0) << (16 - prefix)) + \
                        ((str_data[3] if len(str_data) > 3 else 0) >> (8 - prefix))

                for asc, (word, bit_length) in enumerate(self.HTTP2_HEADERS_HUFFMAN_CODE):
                    if full_width_word_from_current >> (32 - bit_length) == word and (len(str_data) - 1) * 8 >= bit_length - prefix:
                        if asc == 256:
                            str_data = ""
                            break
                        output.append(asc)
                        if bit_length > prefix:
                            str_data = str_data[int(1 + (bit_length - prefix) / 8):]
                            prefix = 8 - (bit_length - prefix) % 8
                        elif bit_length == prefix:
                            str_data = str_data[1:]
                            prefix = 8
                        else:
                            prefix -= bit_length
                        break
                else:
                    break
            return bytes(output)

        def _get_table(header_id):
            if header_id <= len(self.HTTP2_HEADERS_STATIC_TABLE):
                return self.HTTP2_HEADERS_STATIC_TABLE[header_id - 1]
            else:
                return self._http2_dynamic_header_table[header_id - len(self.HTTP2_HEADERS_STATIC_TABLE) - 1]

        while data:
            if data[0] & 128:
                # Indexed header
                header_id = _consume_int(7)
                headers.append(_get_table(header_id))
            elif data[0] & 0b11000000 == 0b01000000:
                # Literal field with incremental indexing
                index = _consume_int(6)
                if index > 0:
                    name = _get_table(index)[0]
                else:
                    name = _consume_str()
                value = _consume_str()
                self._http2_dynamic_header_table.insert(0, (name, value))
                headers.append((name, value))
            elif data[0] & 0b11100000 == 0:
                # Literal field (never indexed or unindexed)
                index = _consume_int(4)
                if index > 0:
                    name = _get_table(index)[0]
                else:
                    name = _consume_str()
                value = _consume_str()
                headers.append((name, value))
            elif data[0] & 0b11100000 == 0b00100000:
                size = _consume_int(5)
            else:
                raise ValueError("Invalid data received as header: %s" % bin(data[0]))

        return headers

    def hpack_encode(self, headers):
        def _encode_header(key, value):
            key = key.lower()
            def _encode_int(integer, prefix=8):
                if integer < (1 << prefix) - 1:
                    return bytes((integer,))
                out = [ chr((1<<prefix) - 1) ]
                integer -= ((1<<prefix) - 1)
                while integer >= 128:
                    out.append(128 + (integer % 128))
                    integer /= 128
                out.append(integer)
                return b"".join(out)

            def _encode_str_literal(st):
                return _encode_int(len(st), 7) + st

            return b"".join((b"\0", _encode_str_literal(key), _encode_str_literal(value)))

        header_lines = headers.split(b"\r\n")
        output = []

        first_line = header_lines[0].split()
        status_code = first_line[1]

        output.append(_encode_header(b":status", status_code))

        for line in header_lines[1:]:
            if b":" in line:
                key, value = line.split(b":", 1)
                output.append(_encode_header(key.strip(), value.strip()))
            else:
                line = line.strip()
                if line:
                    output.append(_encode_header(key.strip(), line))

        return b"".join(output)


    def http2_initiate(self, stream_id, stream):
        sock1, sock2 = socket.socketpair()

        def _thread(sock, client_address, server):
            try:
                HttpHandler(sock, client_address, server, options=self.options, use_gzip=False)
            finally:
                sock.close()
        handler_thread = threading.Thread(target=_thread, args=(sock2, self.client_address, self.server))
        handler_thread.start()
        stream["handler_thread"] = handler_thread

        def _communicate(stream_id, sock):
            state = 0
            str_buffer = b""
            while True:
                try:
                    data = sock.recv(10240)
                except IOError:
                    break
                if not data:
                    break

                if state == 0:
                    str_buffer += data
                    if b"\r\n\r\n" not in str_buffer:
                        continue
                    state = 1
                    headers, data = str_buffer.split(b"\r\n\r\n", 1)
                    headers_send = self.hpack_encode(headers)
                    length_hi = (len(headers_send) & 0xff0000) >> 16
                    length_lo = len(headers_send) & 0xffff
                    # HEADERS frame (type = 1), flags = 4 (END_HEADERS)
                    self.wfile.write(struct.pack("!BHBBI", length_hi, length_lo, 1, 4, stream_id) + headers_send)

                if state == 1 and data:
                    length_hi = (len(data) & 0xff0000) >> 16
                    length_lo = len(data) & 0xffff
                    # DATA frame (type = 0), flags = 0
                    self.wfile.write(struct.pack("!BHBBI", length_hi, length_lo, 0, 0, stream_id) + data)

            # DATA frame (type = 0), flags = 1 (END_STREAM)
            self.wfile.write(struct.pack("!BHBBI", 0, 0, 0, 1, stream_id))

        communication_thread = threading.Thread(target=_communicate, args=(stream_id, sock1))
        communication_thread.start()
        stream["communication_thread"] = communication_thread

        stream["handler_socket"] = sock1

        hdict = dict(stream["headers"])
        http11_headers =(b"%s %s HTTP/1.1\r\nConnection: close\r\nHost: %s\r\n%s\r\n\r\n" % (hdict[b":method"], hdict[b":path"], hdict[b":authority"], b"\r\n".join((b"%s: %s" % (key, value) for key, value in stream["headers"] if not key.startswith(b":")))))

        sock1.send(http11_headers)

    def handle_http2(self):
        self.log(logging.DEBUG, "This is a http/2 request.")
        self.wfile.write(b"\0\0\0\x04\0\0\0\0\0") # Empty SETTINGS frame
        preface = self.rfile.read(24)
        expected_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        assert preface == expected_preface

        HTTP2_FRAME_TYPES = ( "DATA", "HEADERS", "PRIORITY", "RST_STREAM", "SETTINGS", "PUSH_PROMISE", "PING", "GOAWAY", "WINDOW_UPDATE", "CONTINUATION" )
        HTTP2_ERROR_CODES = ( "NO_ERROR", "PROTOCOL_ERROR", "INTERNAL_ERROR", "FLOW_CONTROL_ERROR", "SETTINGS_TIMEOUT", "STREAM_CLOSED", "FRAME_SIZE_ERROR",
                              "REFUSED_STREAM", "CANCEL", "COMPRESSION_ERROR", "CONNECT_ERROR", "ENHANCE_YOUR_CALM", "INADEQUATE_SECURITY", "HTTP_1_1_REQUIRED" )

        streams = collections.defaultdict(lambda: { "headers": [] })

        while not self.rfile.closed:
            try:
                frame_length_hi, frame_length_lo, frame_type, frame_flags, frame_sid = struct.unpack("!BHBBI", self.rfile.read(9))
            except:
                break
            frame_length = frame_length_lo + (frame_length_hi << 16)
            data = self.rfile.read(frame_length)

            if frame_type == 0: # DATA
                # data contains 1 byte containing how many padding bytes are at the end of the data
                # flags: 1 -> end_stream; 8 -> padded (padding byte is only there in this case!)
                if frame_flags & 8:
                    data = data[1:-struct.unpack("B", data[0])]
                streams[frame_sid]["handler_socket"].send(data)
                if frame_flags & 1:
                    streams[frame_sid]["handler_socket"].shutdown(socket.SHUT_WR)
            elif frame_type in (1, 9): # HEADERS, CONTINUATION
                # header block: RFC 7541
                # https://tools.ietf.org/html/rfc7541#page-6
                #
                if frame_flags & 8:
                    data = data[1:-struct.unpack("B", data[0])]
                data = data[4 + (1 if frame_flags & 0x20 else 0):] # Skip stream priority and weight
                streams[frame_sid]["headers"] += self.hpack_decode(data)
                if frame_flags & 4:
                    self.http2_initiate(frame_sid, streams[frame_sid])
                if frame_flags & 1:
                    streams[frame_sid]["handler_socket"].shutdown(socket.SHUT_WR)
            elif frame_type == 3: # RST_STREAM
                if frame_sid in streams:
                    if "handler_socket" in streams[frame_sid]:
                        streams[frame_sid]["handler_socket"].shutdown(socket.SHUT_RDWR)
                    del streams[frame_sid]
            elif frame_type == 4: # SETTINGS
                # TODO Actually handle settings
                if not frame_flags & 1:
                    self.wfile.write(b"\0\0\0\x04\1\0\0\0\0") # Empty SETTINGS frame with ACK flag set
            elif frame_type == 6: # PING
                self.wfile.write(struct.pack("!BHBBI", frame_length_hi, frame_length_lo, 6, 1, frame_sid) + data) # PONG, same frame with ACK flag set
            else:
                self.log(logging.DEBUG, "Ignoring http/2 frame: Length %(len)d, type %(type)s, flags %(flags)d, stream id %(sid)d", len=frame_length,
                         type=HTTP2_FRAME_TYPES[frame_type] if frame_type < len(HTTP2_FRAME_TYPES) else str(frame_type), flags=frame_flags, sid=frame_sid)
    # }}}

    def handle(self):
        self.log(logging.DEBUG, "Accepted connection")
        if hasattr(self.connection, "selected_alpn_protocol") and self.connection.selected_alpn_protocol() == "h2":
            return self.handle_http2()
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
            elif not self.http_version or self.http_version.lower() == b"http/1.0":
                break

    def finish(self):
        try:
            socketserver.StreamRequestHandler.finish(self)
        except:
            pass

class TelnetHandler(socketserver.StreamRequestHandler):
    "A simple shell server"
    logger  = logging.getLogger("telnet")

    def __init__(self, request, client_address, server, options={}):
        self.subprocess_pid = None
        self.pty_fd = None
        self.client_address = client_address
        self.logger.log(logging.INFO, "Incoming connection", { "ip": self.client_address[0] })
        self.options = options
        socketserver.StreamRequestHandler.__init__(self, request, client_address, server)

    def _read_login(self, echo=True):
        user = ""
        while True:
            data = self.connection.recv(1)
            if not data:
                break
            if data == b"\xff":
                self.connection.recv(2)
                continue
            if data == b"\x7f":
                if user:
                    user = user[:-1]
                    if echo:
                        self.connection.send(b"\b \b")
                continue
            if data == b"\r":
                self.connection.send(b"\n\r")
                break
            if data[0] < 32 or data[0] > 250:
                continue
            user += data.decode()
            if echo:
                self.connection.send(data)
        return user

    def handle_authentication(self, correct_user, correct_password):
        self.connection.send(b"\033[1;32miwebd telnet server\033[0m\n\n\r\033[1m%s\033[0m login: " % socket.gethostname().encode())
        user = self._read_login()
        if not user:
            return False
        self.connection.send(b"password: ")
        password = self._read_login(False)
        if not password:
            return False
        if (correct_user and user != correct_user) or password != correct_password:
            time.sleep(2)
            self.connection.send(b"\n\n\r\033[31mLogin incorrect.\033[0m\r\n")
            time.sleep(1)
            return False
        else:
            time.sleep(1)
            self.connection.send(b"\r\n")
            return True

    def handle(self):
        self.connection.send(b"\xff\xfb\x01\xff\xfb\x03") # IAC - Will - echo - IAC - Will - supress go ahead

        if "pass" in self.options and self.options["pass"]:
            if not self.handle_authentication(self.options["user"], self.options["pass"]):
                self.logger.log(logging.WARNING, "Authentication failure", { "ip": self.client_address[0] })
                self.connection.shutdown(socket.SHUT_RDWR)
                return

        pid, fd = pty.fork()
        if not pid:
            os.execv(os.environ["SHELL"], (os.environ["SHELL"], "-"))
            sys.exit(1)
        self.pty_fd = fd
        self.subprocess_pid = pid

        child_thread = threading.Thread(target=self._sub_to_sock_thread)
        child_thread.start()

        while True:
            data = self.connection.recv(10240)
            while data and data[0] == b"\xff":
                command = data[:3]
                data = data[3:]
                self.logger.debug("Received command: %(command)d %(parameter)d", {"ip": self.client_address[0], "command": ord(command[1]), "parameter": ord(command[2])})
                if not data:
                    data = self.connection.recv(10240)
            if not data:
                break
            os.write(self.pty_fd, data)
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except:
            pass

        os.close(self.pty_fd)
        self.pty_fd = None
        child_thread.join()

    def _sub_to_sock_thread(self):
        while True:
            try:
                data = os.read(self.pty_fd, 10240)
            except:
                break
            if not data:
                break
            self.connection.send(data)
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except:
            pass

    def finish(self):
        if self.subprocess_pid:
            os.kill(self.subprocess_pid, signal.SIGHUP)
        if self.pty_fd:
            os.close(self.pty_fd)

def xml_escape(string):
    "Escape special XML/HTML characters"
    return string.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;")

def xml_unescape(string):
    "Unescape special XML/HTML characters"
    return string.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", '"').replace("&apos;", "'")

def format_size(size):
    "Format a human-readable file size"
    prefix = ""
    for prefix in ("", "K", "M", "G", "T"):
        if size < 1024:
            break
        size /= 1024.
    return "%2.2f %sBi" % (size, prefix)

def file_read(fileobj, amount):
    return fileobj.read(amount)

def file_write(fileobj, data):
    tries = 100
    while True:
        try:
            fileobj.write(data)
        except IOError as e:
            if e.errno == errno.EAGAIN:
                continue
            if e.errno == errno.EINTR:
                tries -= 1
                if not tries:
                    raise
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
        if has_ctypes:
            try:
                source_file.fileno()
                if os.fstat(target_file.fileno()).st_mode & 0o140000: # S_IFSOCK
                    # Source file has an fd, target is a socket, and ctypes is available - use sendfile!
                    original_length = length
                    while length > 0:
                        written = libc.sendfile(target_file.fileno(), source_file.fileno(), 0, length)
                        if written <= 0:
                            errno = ctypes.get_errno()
                            if errno in (errno.EINVAL, errno.ENOSYS) and original_length == length:
                                # sendfile() man-page tells us to fallback to a read/write loop
                                break
                            raise IOError(errno, "sendfile() failed [%s]" % errno.errorcode[errno])
                        length -= written
            except (io.UnsupportedOperation, AttributeError):
                pass

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
    evt = threading.Event()
    signal_count = 0
    def _signal_handler(signum, frame):
        nonlocal signal_count
        evt.set()
        signal_count += 1
        if signal_count == 1:
            logging.warn("Signal received. Shutting down server sockets.")
            for server in servers:
                if not server:
                    pass
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
    evt.wait()
    while threading.active_count() > 1 + extra_thread_count:
        print("\r\033[JWaiting for %d remaining conntections to terminate." % (threading.active_count() - 1 - extra_thread_count, ), end=' ')
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
        urllib.request.urlretrieve(url, cache_file)
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
        return { "httpd": 80, "ftpd": 21, "httpsd": 443, "telnetd": 23 }[service]
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

_iterate_interfaces_lock = threading.Lock()

def iterate_interfaces():
    if not hasattr(libc, "getifaddrs"):
        return

    class Ifap(ctypes.Structure):
        _fields_ = [("ifa_next", ctypes.c_void_p),
                    ("ifa_name", ctypes.c_char_p),
                    ("ifa_flags", ctypes.c_int),
                    ("ifa_addr", ctypes.c_void_p)]

    ptype = ctypes.POINTER(Ifap)
    ifap = ptype()
    libc.getifaddrs(ctypes.byref(ifap))
    ptr = ifap
    while ptr:
        if_name = ptr.contents.ifa_name.decode()
        addr = ctypes.c_buffer(b"", 255)
        if not ptr.contents.ifa_addr:
            ptr = ctypes.cast(ptr.contents.ifa_next, ptype)
            continue
        addr_type = ctypes.cast(ptr.contents.ifa_addr, ctypes.POINTER(ctypes.c_short)).contents.value
        if addr_type not in (2, 10):
            ptr = ctypes.cast(ptr.contents.ifa_next, ptype)
            continue
        libc.getnameinfo(ptr.contents.ifa_addr, 16 if addr_type == 2 else 30, addr, 255, ctypes.cast(0, ctypes.c_char_p), 0, 1)
        ip = addr.value.decode()
        ptr = ctypes.cast(ptr.contents.ifa_next, ptype)
        yield if_name, ip
    libc.freeifaddrs(ifap)

def dlna_handler(ips, name, additional_options, port, avahi_name_http, avahi_name_webdav):
    announcements = [
        "\r\n".join(["CACHE-CONTROL: max-age=1800", "LOCATION: http://{ip}:{port}/.well-known/dlna/description.xml",
            "NT: urn:schemas-upnp-org:service:ContentDirectory:1", "SERVER: UPnP/1.0, iwebd",
            "USN: uuid:2f71654a-4ed0-486d-96a8-5185f96dea1e::urn:schemas-upnp-org:service:ContentDirectory:1", "", ""]),
        "\r\n".join(["CACHE-CONTROL: max-age=1800", "LOCATION: http://{ip}:{port}/.well-known/dlna/description.xml",
            "NT: urn:schemas-upnp-org:service:MediaServer:1", "SERVER: UPnP/1.0, iwebd",
            "USN: uuid:2f71654a-4ed0-486d-96a8-5185f96dea1e::urn:schemas-upnp-org:service:MediaServer:1", "", ""]),
        "\r\n".join(["CACHE-CONTROL: max-age=1800", "LOCATION: http://{ip}:{port}/.well-known/dlna/description.xml",
            "NT: uuid:2f71654a-4ed0-486d-96a8-5185f96dea1e", "SERVER: UPnP/1.0, iwebd",
            "USN: uuid:2f71654a-4ed0-486d-96a8-5185f96dea1e", "", ""]),
        "\r\n".join(["CACHE-CONTROL: max-age=1800", "LOCATION: http://{ip}:{port}/.well-known/dlna/description.xml",
            "NT: upnp:rootdevice", "SERVER: UPnP/1.0, iwebd",
            "USN: uuid:2f71654a-4ed0-486d-96a8-5185f96dea1e::upnp:rootdevice",
            "OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01", "", ""]),
    ]
    ifsocks = {}

    for ip in ips:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        for announcement in announcements:
            announcement = "NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nNTS: ssdp:alive\r\n" + announcement
            sock.sendto(announcement.format(ip=ip, port=port[1]).encode(), ("239.255.255.250", 1900))

    for ip in ips:
        if ":" in ip:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)

        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, 1)
        sock.bind(("239.255.255.250", 1900))
        sock.setsockopt(socket.SOL_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
        mreq = socket.inet_aton("239.255.255.250") + socket.inet_aton(ip)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        ifsocks[sock] = ip

    log = logging.getLogger()
    ip_to_source = {}

    while ifsocks:
        readable, _, _ = select.select(list(ifsocks.keys()), [], [], 9999)
        for sock in readable:
            dgram, addr = sock.recvfrom(10240)
            if not dgram:
                del ifsocks[sock]

            source = ip_to_source.get(addr[0])
            if not source:
                tsock = socket.socket(type=socket.SOCK_DGRAM)
                tsock.connect(addr)
                source = tsock.getsockname()[0]
                tsock.close()
                del tsock
                ip_to_source[addr[0]] = source

            if dgram.startswith(b"M-SEARCH"):
                log.debug("Replying to M-SEARCH from %s from %s" % (addr, source))
                for announcement in announcements:
                    r_announcement = "HTTP/1.1 200 OK\r\nExt: \r\n" + announcement
                    sock.sendto(r_announcement.format(ip=source, port=port[1]).replace("NT:", "ST:").encode(), addr)

def main():
    user = False
    password = False

    parser = argparse.ArgumentParser("iwebd", description="Instant web services. Copyright (c) 2015, Phillip Berndt.", epilog="You must supply at least one of the server options.", add_help=False)
    parser.add_argument("-f", nargs="?", default=False, type=partial(hostportpair, "ftpd"), help="Run ftpd", metavar="port")
    parser.add_argument("-h", nargs="?", default=False, type=partial(hostportpair, "httpd"), help="Run httpd", metavar="port")
    if has_ssl:
        parser.add_argument("-H", nargs="?", default=False, type=partial(hostportpair, "httpsd"), help="Run httpsd / http2d", metavar="port")
    parser.add_argument("-t", nargs="?", default=False, type=partial(hostportpair, "telnetd"), help="Run telnetd", metavar="port")
    parser.add_argument("-T", nargs="?", default=False, type=partial(hostportpair, "telnetd"), help="Reverse telnet", metavar="remote")
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
    parser.add_argument("--dlna", action="store_true", help="Announce the httpd via dlna/UPnP")
    parser.add_argument("--help", action="help", help="Display this help")
    parser.add_argument("--root", help="root directory to serve from", metavar="directory")
    options = vars(parser.parse_args(sys.argv[1:]))

    if options["f"] is False and options["h"] is False and ("H" not in options or options["H"] is False) and options["t"] is False and options["T"] is False:
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

    locale.setlocale(locale.LC_ALL, "C")

    cgi_handlers = determine_available_cgi_handlers()

    server_options = {
        "write_access": options["w"],
        "dav_enabled": options["d"],
        "live_reload_enabled": has_pyinotify and options["live_reload"],
        "user": user,
        "pass": password,
        "allow_cgi": options["c"],
        "cgi_handlers": cgi_handlers,
        "alpn_protocols": None,
        "dlna": options["dlna"],
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
        http_variants.append(("HTTPS", {"ssl_wrap": ssl_key, "alpn_protocols": ["h2", "http/1.1"]}, options["H"] or ("", default_port("httpsd")), "https", "webdavs"))

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

    if options["dlna"] and http_variants:
        dlna_thread = threading.Thread(target=dlna_handler, args=[ [x[1] for x in iterate_interfaces() ] ] + list(http_variants[0]))
        dlna_thread.daemon = True
        dlna_thread.start()
        extra_thread_count += 1

    if options["f"] is not False:
        server, ftpd_port = setup_tcp_server(FtpHandler, options["f"] or ("", default_port("ftpd")), server_options)
        servers.append(server)
        logger.info("%(what)s server started on %(port)s", {"what": "FTP", "port": ":".join(map(str, ftpd_port))})
        if "a" in options and options["a"]:
            create_avahi_group("ftp", ftpd_port[1])

    if options["t"] is not False:
        server, telnetd_port = setup_tcp_server(TelnetHandler, options["t"] or ("", default_port("telnetd")), server_options)
        servers.append(server)
        logger.info("%(what)s server started on %(port)s", {"what": "Telnet", "port": ":".join(map(str, telnetd_port))})

    if options["T"] is not False:
        remote_socket = socket.socket()
        remote_socket.connect(options["T"])
        threading.Thread(target=TelnetHandler, args=(remote_socket, options["T"], None, server_options)).start()
        logger.info("%(what)s reverse connected to %(remote)s", {"what": "Telnet", "remote": ":".join(map(str, options["T"]))})

    if servers and options["v"]:
        if not has_pyinotify:
            logging.getLogger("autoreload").debug("pyinotify unavailable. Not running autoreload thread.")
        else:
            ar_thread = threading.Thread(target=autoreload, args=(os.getpid(), script_file_name,))
            ar_thread.daemon = True
            ar_thread.start()
            extra_thread_count += 1

    if servers:
        interfaces = [ (ifname, ip) for ifname, ip in iterate_interfaces() if ip and ifname != "lo" ]
        if interfaces:
            logging.info("Serving on the following IPs:")
            for ifname, group in itertools.groupby(sorted(interfaces), lambda x: x[0]):
                logging.info(" - %15s: %s", ifname, ", ".join([ x[1] for x in group ]))

    wait_for_signal(servers, extra_thread_count, script_file_name)

if __name__ == '__main__':
    main()

