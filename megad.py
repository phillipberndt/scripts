#!/usr/bin/env python
# encoding: utf-8
#
# Gigantic and monolitic httpd and ftpd and everything else that makes a move from b to c
# Copyright (c) 2015, Phillip Berndt
#
import SocketServer
import StringIO
import datetime
import getopt
import logging
import mimetypes
import os
import pwd
import signal
import socket
import sys
import threading
import time
import traceback

try:
    import gtk
    has_gtk = True
except ImportError:
    has_gtk = False

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
    # See http://tools.ietf.org/html/rfc959
    #     http://cr.yp.to/ftp/list/eplf.html
    logger  = logging.getLogger("ftp")

    def __init__(self, request, client_address, server, options={}):
        self.user = None
        self.is_authenticated = False
        self.current_path = ""
        self.data_mode = { "mode": "PORT", "ip": client_address, "port": 20, "socket": None, "server_socket": None }

        self.options = options
        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)

        #self.pasv_socket = setup_tcp_server_socket(1234 if "port" not in options else options["port"])

    def reply(self, line):
        if "\n" in line:
            lines = line.split("\n")
            code, rest = line[0].split(None, 1)
            lines = [ "%s-%s" % (code, rest) ] + lines[1:-1] + [ "%s %s" % (code, lines[-1]) ]
            self.wfile.write("%s\n" % "\n".join(lines))
        else:
            self.wfile.write("%s\n" % line)

    def connect_data_socket(self):
        if not self.data_mode["socket"]:
            if self.data_mode["mode"] == "PORT":
                self.data_mode["socket"] = socket.socket()
                self.data_mode["socket"].connect((self.data_mode["ip"], self.data_mode["port"]))
            else:
                data_socket, remote = self.data_mode["server_socket"].accept()
                logger.debug("Data connection from %s for %s accepted" % (remote, self.client_address))
                self.data_mode["socket"] = data_socket

    def disconnect_data_socket(self):
        if self.data_mode["socket"]:
            self.data_mode["socket"].shutdown(socket.SHUT_RDWR)
            self.data_mode["socket"] = None

    def reply_with_file(self, file):
        self.reply("150 File status okay; about to open data connection.")
        try:
            self.connect_data_socket()
        except:
            self.reply("425 Can't open data connection.")
            return
        try:
            fd_copy(file, self.data_mode["socket"].makefile("w"), -1)
        except socket.error:
            self.reply("426 Connection closed; transfer aborted.")
            return
        self.reply("226 Closing data connection.")
        self.disconnect_data_socket()

    def build_path(self, path, expect_file=False):
        if not path:
            return self.current_path
        if path[0] == '"' and path[-1] == '"':
            path = path[1:-1]
        if path[0] == "/":
            new_path = "%s/" % os.path.abspath(".%s" % path)
        else:
            new_path = "%s/" % os.path.abspath(os.path.join(self.current_path, path))
        base_path = "%s/" % os.path.abspath(".")
        if expect_file:
            new_path = new_path[:-1]
            check = os.path.isfile
        else:
            check = os.path.isdir
        if new_path[:len(base_path)] != base_path or not check(new_path):
            self.reply("550 No such file or directory.")
            return False
        return new_path[len(base_path):]

    def handle(self):
        logger.debug("Incoming FTP connection from %s" % (str(self.client_address), ))
        self.reply("220 Service ready for new user.")
        while True:
            command = self.rfile.readline().strip()
            if not command:
                break
            logger.debug("%s: %s" % (self.client_address, command))
            command = command.split(None, 1)

            # Authentication
            if command[0] == "USER":
                if "user" in options and command[1] != options["user"]:
                    self.reply("430 Invalid username or password")
                elif "pass" in options:
                    self.reply("331 User name okay, need password.")
                    self.user = command[1]
                else:
                    self.reply("230 User logged in, proceed.")
                    self.user = command[1]
                    self.is_authenticated = True
                continue
            elif command[0] == "PASS" and self.user:
                self.reply("230 User logged in, proceed.")
                self.is_authenticated = True
                continue
            elif command[0] == "NOOP":
                self.reply("200 No operation.")
                continue
            else:
                if not self.is_authenticated:
                    self.reply("530 Not logged in")
                    continue

            # Commands that do not require write permissions
            if command[0] == "SYST":
                self.reply("215 UNIX")
            elif command[0] == "QUIT":
                self.reply("221 Goodbye")
                break
            elif command[0] == "TYPE":
                self.reply("202 Command not implemented, superfluous at this site.")
            elif command[0] == "MODE":
                if command[1] != "Stream":
                    self.reply("504 Command not implemented for that parameter.")
                else:
                    self.reply("200 Fine with me")
            elif command[0] == "STRU":
                if command[1] != "File":
                    self.reply("504 Command not implemented for that parameter.")
                else:
                    self.reply("200 Fine with me")
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
            elif command[0] == "LIST":
                response = StringIO.StringIO()

                if len(command) > 1:
                    path_components = [ x for x in command[1].split(" ") if x[0] != "-" ]
                    path_string = " ".join(path_components)
                    path = self.build_path(path_string)
                    if path == False:
                        continue
                else:
                    path = self.current_path

                for element in os.listdir(path or "."):
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
                        stat.st_gid,
                        stat.st_size,
                        mtime.strftime("%b"),
                        mtime.strftime("%d"),
                        mtime.strftime("%H:%I") if mtime.strftime("%Y") == datetime.datetime.today().strftime("%Y") else  mtime.strftime("%Y"),
                        element))
                response.seek(0)
                self.reply_with_file(response)
            elif command[0] == "PWD":
                self.reply("257 \"/%s\"" % self.current_path)
            elif command[0] == "CWD":
                new_path = self.build_path(command[1])
                if new_path == False:
                    continue
                self.current_path = new_path
                self.reply("200 \"/%s\"" % self.current_path)
            elif command[0] == "RETR":
                which_file = self.build_path(command[1], True)
                if which_file == False:
                    continue
                self.reply_with_file(open(which_file, "r"))
            elif command[0] == "CDUP":
                self.current_path = "/".join(self.current_path.split("/")[:-1])
                self.reply("200 \"/%s\"" % self.current_path)
            else:
                self.reply("502 Command not implemented.")

            # USER <SP> <username> <CRLF>
            # PASS <SP> <password> <CRLF>
            # ACCT <SP> <account-information> <CRLF>
            # CWD  <SP> <pathname> <CRLF>
            # CDUP <CRLF>
            # SMNT <SP> <pathname> <CRLF>
            # QUIT <CRLF>
            # REIN <CRLF>
            # PORT <SP> <host-port> <CRLF>
            # PASV <CRLF>
            # TYPE <SP> <type-code> <CRLF>
            # STRU <SP> <structure-code> <CRLF>
            # MODE <SP> <mode-code> <CRLF>
            # RETR <SP> <pathname> <CRLF>
            # STOR <SP> <pathname> <CRLF>
            # STOU <CRLF>
            # APPE <SP> <pathname> <CRLF>
            # ALLO <SP> <decimal-integer>
            #     [<SP> R <SP> <decimal-integer>] <CRLF>
            # REST <SP> <marker> <CRLF>
            # RNFR <SP> <pathname> <CRLF>
            # RNTO <SP> <pathname> <CRLF>
            # ABOR <CRLF>
            # DELE <SP> <pathname> <CRLF>
            # RMD  <SP> <pathname> <CRLF>
            # MKD  <SP> <pathname> <CRLF>
            # PWD  <CRLF>
            # LIST [<SP> <pathname>] <CRLF>
            # NLST [<SP> <pathname>] <CRLF>
            # SITE <SP> <string> <CRLF>
            # SYST <CRLF>
            # STAT [<SP> <pathname>] <CRLF>
            # HELP [<SP> <string>] <CRLF>
            # NOOP <CRLF>

#            Connection Establishment
#               120
#                  220
#               220
#               421
#            Login
#               USER
#                  230
#                  530
#                  500, 501, 421
#                  331, 332
#               PASS
#                  230
#                  202
#                  530
#                  500, 501, 503, 421
#                  332
#               ACCT
#                  230
#                  202
#                  530
#                  500, 501, 503, 421
#               CWD
#                  250
#                  500, 501, 502, 421, 530, 550
#               CDUP
#                  200
#                  500, 501, 502, 421, 530, 550
#               SMNT
#                  202, 250
#                  500, 501, 502, 421, 530, 550
#            Logout
#               REIN
#                  120
#                     220
#                  220
#                  421
#                  500, 502
#               QUIT
#                  221
#                  500
#            Transfer parameters
#               PORT
#                  200
#                  500, 501, 421, 530
#               PASV
#                  227
#                  500, 501, 502, 421, 530
#               MODE
#                  200
#                  500, 501, 504, 421, 530
#               TYPE
#                  200
#                  500, 501, 504, 421, 530
#               STRU
#                  200
#                  500, 501, 504, 421, 530
#            File action commands
#               ALLO
#                  200
#                  202
#                  500, 501, 504, 421, 530
#               REST
#                  500, 501, 502, 421, 530
#                  350
#               STOR
#                  125, 150
#                     (110)
#                     226, 250
#                     425, 426, 451, 551, 552
#                  532, 450, 452, 553
#                  500, 501, 421, 530
#               STOU
#                  125, 150
#                     (110)
#                     226, 250
#                     425, 426, 451, 551, 552
#                  532, 450, 452, 553
#                  500, 501, 421, 530
#               RETR
#                  125, 150
#                     (110)
#                     226, 250
#                     425, 426, 451
#                  450, 550
#                  500, 501, 421, 530
#               LIST
#                  125, 150
#                     226, 250
#                     425, 426, 451
#                  450
#                  500, 501, 502, 421, 530
#               NLST
#                  125, 150
#                     226, 250
#                     425, 426, 451
#                  450
#                  500, 501, 502, 421, 530
#               APPE
#                  125, 150
#                     (110)
#                     226, 250
#                     425, 426, 451, 551, 552
#                  532, 450, 550, 452, 553
#                  500, 501, 502, 421, 530
#               RNFR
#                  450, 550
#                  500, 501, 502, 421, 530
#                  350
#               RNTO
#                  250
#                  532, 553
#                  500, 501, 502, 503, 421, 530
#               DELE
#                  250
#                  450, 550
#                  500, 501, 502, 421, 530
#               RMD
#                  250
#                  500, 501, 502, 421, 530, 550
#               MKD
#                  257
#                  500, 501, 502, 421, 530, 550
#               PWD
#                  257
#                  500, 501, 502, 421, 550
#               ABOR
#                  225, 226
#                  500, 501, 502, 421
#            Informational commands
#               SYST
#                  215
#                  500, 501, 502, 421
#               STAT
#                  211, 212, 213
#                  450
#                  500, 501, 502, 421, 530
#               HELP
#                  211, 214
#                  500, 501, 502, 421
#            Miscellaneous commands
#               SITE
#                  200
#                  202
#                  500, 501, 530
#               NOOP
#                  200
#                  500 421

# TODO FTP server
# TODO Avahi announcement
# TODO ngrok support (?!)

class HttpHandler(SocketServer.StreamRequestHandler):
    # TODO CGI support
    # TODO Webdav support
    timeout = 10
    logger  = logging.getLogger("http")

    def __init__(self, request, client_address, server, options={}):
        self.headers = {}
        self.options = options
        SocketServer.StreamRequestHandler.__init__(self, request, client_address, server)

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

options = {}

server, port = setup_tcp_server(HttpHandler, 1234, options)
servers.append(server)
logger.info("HTTP server started on port %d", port)

server, port = setup_tcp_server(FtpHandler, 1235, options)
servers.append(server)
logger.info("HTTP server started on port %d", port)

wait_for_signal(servers)
