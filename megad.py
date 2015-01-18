#!/usr/bin/env python
# encoding: utf-8
#
# Gigantic and monolitic httpd and ftpd and everything else that makes a move from b to c
# Copyright (c) 2015, Phillip Berndt
#
import SocketServer
import StringIO
import getopt
import logging
import mimetypes
import os
import signal
import socket
import sys
import threading
import traceback
import time

try:
    import gtk
    has_gtk = True
except ImportError:
    has_gtk = False

class ReusableServer(SocketServer.ThreadingTCPServer):
    allow_reuse_address = True

# TODO FTP server
# TODO Avahi announcement
# TODO ngrok support (?!)

class HttpHandler(SocketServer.StreamRequestHandler):
    # TODO CGI support
    # TODO Webdav support
    timeout = 10
    logger  = logging.getLogger("http")

    def __init__(self, *args):
        self.headers = {}
        SocketServer.StreamRequestHandler.__init__(self, *args)

    def setup(self):
        SocketServer.StreamRequestHandler.setup(self)
        self.processing_started = time.time()

    def read_http_method(self):
        line = self.rfile.readline()
        if not line:
            return False
        self.method, self.path, self.http_version = line.split()
        if self.http_version.lower() not in "http/1.1":
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

    def send_error(self, error_message, force_close=False, details=""):
        if ("content-length" in self.headers or "transfer-encoding" in self.headers) and not ("expect" in self.headers and "100-continue" in self.headers["expect"]):
            force_close = True
        if force_close:
            self.headers["connection"] = [ "close" ]
        body = "<!DOCTYPE HTML><title>%s</title><body><h1>%s</h1><pre>%s</pre>" % (error_message, error_message, html_escape(details))
        connection_mode = self.headers["connection"][0] if "connection" in self.headers else "Keep-Alive"
        self.wfile.write("\r\n".join([
            "%s %s" % (self.http_version, error_message),
            "Content-Length: %d" % len(body),
            "Content-Type: text/html",
            "Host: %s" % self.headers["host"][0],
            "Connection: %s" % connection_mode,
            "",
            ""]))
        self.wfile.write(body)

    def handle_request_for_file(self):
        if os.path.isdir(self.mapped_path):
            mime_type = "text/html"
            data = [ "<!DOCTYPE HTML><title>Directory contents for %(path)s</title><body><h1>Directory contents for %(path)s</h1><ul>" % { "path": html_escape(self.path) } ]
            base = self.path + ("/" if self.path[-1] != "/" else "")
            data.append("<li><a href='%s'>..</a></li>" % html_escape(os.path.join(base, "..")))

            dirs = []
            files = []

            for name in os.listdir(self.mapped_path):
                absname = os.path.join(self.mapped_path, name)
                if os.path.isdir(absname):
                    dirs.append("<li><a href='%s'>%s/</a></li>" % (html_escape(os.path.join(base, name)), html_escape(name)))
                else:
                    file_mime_type = mimetypes.guess_type(absname)[0] or "application/octet-stream"
                    if has_gtk and gtk.icon_theme_get_default().has_icon(file_mime_type.replace("/", "-")):
                        files.append("<li><img src='/.directory-icons/%s'> <a href='%s'>%s</a></li>" % (file_mime_type.replace("/", "-"), html_escape(os.path.join(base, name)), html_escape(name)))
                    else:
                        files.append("<li><a href='%s'>%s</a></li>" % (html_escape(os.path.join(base, name)), html_escape(name)))

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
        range_header = ""
        start = 0
        if "range" in self.headers:
            req_range_type, req_range = self.headers["range"][0].split("=")
            range_start, range_end = req_range.split("-")
            range_start = int(range_start) if range_start else 0
            range_end = int(range_end) if range_end else (size - 1)
            if req_range_type.lower() != "bytes" or range_start < 0 or range_end < range_start or range_end > size:
                print self.headers["range"]
                self.send_error("416 Range Not Satisfiable")
                return
            status = "206 Partial Content"
            range_header = "Content-Range: bytes %d-%d/%d\r\n" % (range_start, range_end, size)
            start = range_start
            size = range_end - range_start + 1

        file.seek(start)

        connection_mode = self.headers["connection"][0] if "connection" in self.headers else "Keep-Alive"
        self.wfile.write("\r\n".join([
            "%s %s" % (self.http_version, status),
            "Content-Length: %d" % size,
            "Content-Type: %s" % mime_type,
            "Accept-Ranges: bytes",
            "Host: %s" % self.headers["host"][0],
            "Connection: %s" % connection_mode,
            range_header,
            ""]))
        fd_copy(file, self.wfile, size)
        file.close()


    def handle_request(self):
        if not self.read_http_method():
            self.rfile.close()
            return
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

        cwd = os.path.abspath(".")
        self.mapped_path = os.path.join(cwd, self.path[1:])
        if "?" in self.mapped_path:
            self.mapped_path = self.mapped_path.split("?")[0]

        if self.mapped_path[:len(cwd)] != cwd:
            self.send_error("403 Access denied")
            return

        self.read_http_body()

        if not os.path.exists(self.mapped_path):
            logging.warn("[%s] 404 %s" % (self.client_address, self.path))
            self.send_error("404 Not found")
            return

        logging.info("[%s] %s" % (self.client_address, self.path))

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
            if "connection" in self.headers and self.headers["connection"][0].lower() != "keep-alive":
                break

    def finish(self):
        try:
            SocketServer.StreamRequestHandler.finish(self)
        except:
            pass

def html_escape(string):
    return string.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

def fd_copy(source_file, target_file, length):
    buffer = 10240
    while length > 0:
        data = source_file.read(min(buffer, min(length, 10240)))
        if not data:
            raise IOError("Failed to read data")
        if target_file:
            target_file.write(data)
        length -= len(data)

def setup_tcp_server(handler_class, base_port=1234):
    counter = 0
    while True:
        try:
            server = ReusableServer(("", base_port + counter), handler_class)
            break
        except socket.error:
            counter += 1
            if counter > 100:
                raise
    threading.Thread(target=server.serve_forever).start()
    return server, base_port + counter

def wait_for_signal(servers):
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




logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("main")

servers = []
server, port = setup_tcp_server(HttpHandler, 1234)
servers.append(server)
logger.info("HTTP server started on port %d", port)

wait_for_signal(servers)
