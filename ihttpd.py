#!/usr/bin/python
import glib
import socket
import sys
import os
import subprocess
import signal
try:
	import cStringIO as StringIO
except:
	import StringIO
import datetime
import base64
import mimetypes
import re
import time
import fcntl
import wsgiref.handlers

# GTK for file icon generation
has_gtk = False
try:
	import gio, gtk
	has_gtk = True
except:
	pass

"""
	A simple HTTP daemon
	For testing purposes

	Start using
	 python ihttpd.py <port>
	
	It will serve files from the current directory and below.
	It has support for a limited subset of HTTP only!
	Features:
	
	 * CGI (PHP/Perl are preconfigured)
	 * Partial "Range" requests
	 * Keep-Alive
	 * Non-Threaded, Non-Forking - uses "select" calls for concurrency
	   This should give it good scaling abilities
	 * Caching (If-Modified-Since)
	 * URL Rewriting (Parses the RewriteRules in htaccess files
	      to search for a map for non-existing files)
"""

# Define CGI handlers
cgi_handlers = {
	"php": "/usr/bin/php5-cgi",
	"pl": "/usr/bin/perl",
	"py": "/usr/bin/python"
}

# URL rewriting
def rewrite_url(path):
	new_path = "/"
	for component in path[1:].split("/"):
		new_path += component + "/"
		if os.path.isdir(new_path) and os.path.exists(new_path + ".htaccess"):
			basedir = new_path[:-1]
			for line in open(new_path + ".htaccess").readlines():
				base_match = re.match("\s*RewriteBase\s+(.+?)\s*", line)
				if base_match:
					basedir = base_match.group(1)
				# TODO Support for flags, conditions
				rule_match = re.match("\s*RewriteRule\s+(\S+)\s+(\S+).*", line)
				if rule_match:
					match_against = path[len(basedir):] if path[:len(basedir)] == basedir else path
					if match_against and match_against[0] == "/":
						match_against = match_against[1:]
					if re.match(rule_match.group(1), match_against):
						path = new_path + re.sub(rule_match.group(1), rule_match.group(2).replace("$", "\\"), match_against)
						if "?" in match_against and "?" in rule_match.group(2):
							components = path.split("?", 2)
							path = components[0] + "?" + components[1] + "&" + components[2]
	return path

# Format a timestamp
def format_timestamp(date_object):
	return wsgiref.handlers.format_date_time(time.mktime(date_object.timetuple()))

# Class for connection handling
class Connection(object):
	instances = 0

	def __str__(self):
		return ":".join(map(str, self.remote_addr))

	def __init__(self, socket, ip):
		self.socket = socket
		self.socket_fileno = socket.fileno()
		self.remote_addr = ip
		self.data_cache = ""
		self.hup_done = False
		self._restart_handlers(30)
		self.allow_crlf = False
		Connection.instances += 1
	
	def _restart_handlers(self, timeout):
		self.state = 1
		self.allow_crlf = True
		self.request_headers = {}
		self.request_type = ""
		self.request_uri = ""
		self.cgi_process = False
		self.event_ids = []
		self.timeout_id = False
		self.allow_keep_alive = True
		self.do_chunk = False
		self.latest_header = False
		self.event_ids.append(glib.io_add_watch(self.socket, glib.IO_IN, lambda fd, cond: self.handle_incoming() or True))
		self.event_ids.append(glib.io_add_watch(self.socket, glib.IO_HUP, lambda fd, cond: self.handle_hup() or True))
		self.timeout_id = glib.timeout_add(timeout * 1000, self.handle_timeout)

	# Format HTTP Headers for output. Has side-effects!
	def _headers(self, status, input_headers):
		if type(input_headers) is str:
			input_headers = input_headers.replace("\r\n", "\n")
			if input_headers[:7] == "HTTP/1.":
				status, input_headers = input_headers.split("\n", 1)
			headers = {}
			for key, value in (( (y[0].lower(), y[1].strip()) for y in ( x.split(":", 1) for x in input_headers.split("\n") ))):
				if key in headers:
					headers[key] += [ value ]
				else:
					headers[key] = [ value ]
			if "status" in headers:
				status = "HTTP/1.1 " + headers["status"][0]
				del headers["status"]
		else:
			headers = {}
			for key, value in (( (str(x[0]).lower(), str(x[1]).strip()) for x in input_headers.items() )):
				if key in headers:
					headers[key] += [ value ]
				else:
					headers[key] = [ value ]
		if "date" not in headers:
			headers["date"] = [ format_timestamp(datetime.datetime.utcnow()) ]
		status_code = re.search("[0-9]{3}", status)
		if status_code:
			status_code = int(status_code.group(0))
		else:
			status_code = 500
		if "content-length" not in headers:
			if "transfer-encoding" in headers and "chunked" not in headers["transfer-encoding"]:
				self.allow_keep_alive = False
			else:
				headers["transfer-encoding"] = [ "chunked" ]
				self.do_chunk = True
		if not self.allow_keep_alive:
			headers["connection"] = [ "Close" ]
		else:
			headers["connection"] = [ "Keep-Alive" ]
		retval = status + "\r\n"
		for header, values in headers.items():
			for value in values:
				retval += "-".join([ x.capitalize() for x in header.split("-") ]) + ": " + str(value) + "\r\n"
		retval += "\r\n"
		return retval
	
	# Generate HTTP-head section
	def _gen_head(self, title):
		return "<head><meta charset='utf-8'><title>" + title + """</title>
			<style type="text/css">
				body { font-family: sans-serif; }
				td, th { padding: 5px; text-align: left; vertical-align: middle; }
				td img { border: none; }
				th + th { font-weight: normal; }
				td + td { min-width: 300px; }
				td + td + td { min-width: inherit; }
			</style>
			</head>"""

	def handle_timeout(self):
		# Apache does not send this so we don't do that either
		# self.reply_error(408)
		self.handle_hup()

	# Receive incoming data and process it
	def handle_incoming(self, do_receive = True):
		if do_receive:
			try:
				self.data_cache += self.socket.recv(1024)
			except:
				self.handle_hup()
		if self.data_cache == "":
			# HUP
			self.handle_hup()
			return False
		if len(self.data_cache) > 1024 * 512:
			self.reply_error(507)
			self.handle_hup()
			return True
		while self.state < 3 and "\n" in self.data_cache:
			data = self.data_cache.split("\n", 1)
			data, self.data_cache = data
			if data and data[-1] == "\r": data = data[:-1]
			if self.state == 1: # Awaiting first line of request header
				# Some servers send an empty crlf after requests. Ignore that.
				if self.allow_crlf and data == "":
					self.allow_crlf = False
					return True
				request = data.split()
				if len(request) != 3 or (request[2] != "HTTP/1.1" and request[2] != "HTTP/1.0"):
					self.reply_error(400)
					return True
				self.request_type = request[0]
				self.request_uri = request[1]
				self.original_request_uri = re.sub("%([A-F0-9]{2})", lambda x: chr(int(x.group(1), 16)), self.request_uri)

				# URL rewriting and path mapping
				path = os.path.abspath(os.path.join(os.getcwd(), "./" + self.original_request_uri))
				if self.original_request_uri[-1] == "/":
					path += "/"
				# TODO URL rewriting could also be wanted if the file exists..
				if not os.access(path[:path.find("?") if path.find("?") > -1 else len(path)], os.F_OK):
					path = rewrite_url(path)
				if path[:len(os.getcwd())] != os.getcwd():
					self.reply_error(500)
					return True
				self.request_uri = path[len(os.getcwd()):]

				if self.request_uri.find("?") == -1:
					self.request_file = self.request_uri
					self.request_query = ""
				else:
					self.request_file, self.request_query = self.request_uri.split("?", 1)
				self.state = 2
				continue
			if self.state == 2: # Reading headers
				if data == "":
					# Finished.
					self.state = 3
					# Disable timeout
					glib.source_remove(self.timeout_id)
					self.timeout_id = False
					# Reply with an error for unsupported request types
					if self.request_type not in ("POST", "GET", "HEAD"):
						self.reply_error(501)
						return True
					# Check how much more data we have to expect
					if "transfer-encoding" in self.request_headers and self.request_headers["transfer-encoding"] == "chunked":
						# Actually HTTP/1.1 REQUIREs servers to implement chunked encoding, but I have not met any
						# clients which actually use it. So this is not implemented.
						self.reply_error(501)
						return True
					try:
						self.state_3_to_read = int(self.request_headers["content-length"]) if "content-length" in self.request_headers else 0
					except:
						self.reply_error(400)
						return True
					# Check Keep-Alive availability
					self.allow_keep_alive = ("connection" not in self.request_headers or self.request_headers["connection"].lower() != "keep-alive")

					# Handle request if there is no data to read
					self.handle_request()
					break
				if data[0] in (" ", "\t"):
					if self.latest_header:
						self.request_headers[self.latest_header] += "\n" + data.strip()
					else:
						self.reply_error(400)
				else:
					header = data.split(":", 1)
					if len(header) != 2:
						self.reply_error(400)
						return True
					self.latest_header = header[0].lower()
					if self.latest_header in self.request_headers:
						self.request_headers[self.latest_header] += ", " + header[1].strip()
					else:
						self.request_headers[self.latest_header] = header[1].strip()
				if len(self.request_headers) > 100:
					self.reply_error(507)
					return True
		if self.state == 3:
			# Handle POST request data. This does not require line caching
			if self.cgi_process:
				# Forward to CGI process
				send_now = self.data_cache[:self.state_3_to_read]
				try:
					self.cgi_process.stdin.write(send_now)
				except:
					self.reply_error(500)
				self.state_3_to_read -= len(send_now)
				self.data_cache = self.data_cache[len(send_now):]
			else:
				# If there is no CGI-process, ignore the data
				send_now = self.data_cache[:self.state_3_to_read]
				self.state_3_to_read -= len(send_now)
				self.data_cache = self.data_cache[len(send_now):]
				if self.state_3_to_read == 0:
					# TODO We should read the data and ignore it
					# But this does not work out.. instead, for POST requests on
					# ordinary files, we disallow Keep-Alive.
					pass
		return True

	# Hande an actual request
	def handle_request(self):
		# Handle virtual paths, especially directory icons
		if self.request_file[:23] == "/iwebd-directory-icons/" and has_gtk:
			if self.request_type == "POST":
				# This is required because we don't read POST data for this request
				self.allow_keep_alive = False
			try:
				output = StringIO.StringIO()
				def send_data(buf, data=None):
					output.write(buf)
					return True
				gtk.icon_theme_get_default().load_icon(self.request_file[23:], 32, 0).save_to_callback(send_data, "png", {}, None)
				self.socket.send(self._headers("HTTP/1.1 200 Ok", { "Content-Type": "image/png", "Content-Length": output.tell(), "Expires": 
					"Mon, 15 Apr 2030 20:00:00 GMT" }))
				self.socket.send(output.getvalue())
				self.handle_finished()
			except:
				self.reply_error(404)
			return

		# Log all requests for "real" files / directories
		print "[%s] %s" % (self, self.request_uri)
		
		path = os.path.abspath(os.path.join(os.getcwd(), "./" + self.request_file))
		if os.path.isdir(path):
			# Search for directory index
			for index in ("index.html", "index.php", "index.pl", "index"):
				new_path = os.path.join(path, index)
				if os.access(new_path, os.F_OK):
					if self.request_type == "POST":
						# This is required because we don't read POST data for this request
						self.allow_keep_alive = False
					try:
						self.socket.send(self._headers("HTTP/1.1 301 Permanently redirected", { "Content-Length": "0", "Location": os.path.join(self.request_file, index) }))
					except:
						self.handle_hup()
						return
					self.handle_finished()
					return
		if os.path.isdir(path):
			# This is a directory.
			# Redirect to a URL ending in a slash
			if self.request_file and self.request_file[-1] != "/":
				if self.request_type == "POST":
					# This is required because we don't read POST data for this request
					self.allow_keep_alive = False
				try:
					self.socket.send(self._headers("HTTP/1.1 301 Permanently redirected", { "Content-Length": "0", "Location": self.request_file + "/" }))
				except:
					self.handle_hup()
					return
				self.handle_finished()
				return

			# Generate a directory listing
			output_str = ("<!DOCTYPE HTML>%s<body><h1>Directory Listing for %s</h1>") % (self._gen_head("Directory Listing for " +
				self.request_file.replace("<", "&lt;")), self.request_file.replace("<", "&lt;"))
			if self.request_file != "/":
				output_str += "<p><a href='../'>Back to parent directory</a></p>"
			output_str += "<table><tr><td></td><th>File Name</th><th>File Size</th><th>Last modified</th></tr>"
			if has_gtk:
				all_icons = gtk.icon_theme_get_default().list_icons()
			for my_file in filter(lambda x: x[0] != ".", sorted(os.listdir(path))):
				joined = os.path.join(path, my_file)
				try:
					stat = os.stat(joined)
				except:
					continue
				escaped = my_file.replace('"', '&quot;').replace('<', '&lt;')
				# Load size/date
				size_str = stat.st_size
				if size_str > 1024 ** 3:
					size_str = str(round(size_str / 1024 ** 3, 2)) + " GB"
				elif size_str > 1024 ** 2:
					size_str = str(round(size_str / 1024 ** 2, 2)) + " MB"
				elif size_str > 1024:
					size_str = str(round(size_str / 1024, 2)) + " kB"
				else:
					size_str = str(size_str) + " Bytes"
				date_str = datetime.datetime.utcfromtimestamp(stat.st_mtime).strftime("%m-%d-%Y %H:%M:%S")
				if os.path.isdir(joined):
					escaped += "/"
					joined += "/"
				# Load icon
				if has_gtk:
					icon = filter(lambda x: x in all_icons, gio.content_type_get_icon(gio.content_type_guess(joined, None, min(stat.st_size, 2**16 - 1))[0]).get_names())
					if len(icon) > 0:
						icon = '<img src="/iwebd-directory-icons/' + icon[0] + '">'
					else:
						icon = ""
				else:
					icon = ""
				output_str += '<tr><td>%s</td><td><a href="%s">%s</a></td><td>%s</td><td>%s</td></tr>' % (icon, escaped, escaped, size_str, date_str)
			output_str += "</table></body>"
			output = StringIO.StringIO(output_str)
			def send_data():
				write = output.read(1024 * 512)
				if not write:
					self.handle_finished()
					return
				try:
					self.socket.send(write)
				except:
					self.handle_hup()
					return
			if self.request_type == "POST":
				# This is required because we don't read POST data for this request
				self.allow_keep_alive = False
			response_headers = {
				"Content-Length": len(output_str),
				"Content-Type": "text/html; charset=utf-8"
			}
			try:
				self.socket.send(self._headers("HTTP/1.1 200 Ok", response_headers)) 
			except:
				self.handle_hup()
				return
			if self.request_type == "HEAD":
				self.handle_finished()
				return
			self.event_ids.append(glib.io_add_watch(self.socket, glib.IO_OUT, lambda fd, cond: send_data() or True))
		elif os.access(path, os.F_OK):
			# File exists.
			# Handle as CGI if applicable
			extension = os.path.splitext(path)[1][1:]
			if extension in cgi_handlers:
				self.handle_cgi([cgi_handlers[extension], path])
				return

			if self.request_type == "POST":
				# This is required because we don't read POST data for this request
				self.allow_keep_alive = False

			# Send the file back to the user
			response_file = open(path, "r")

			# GTK has better mime-type guessing
			if has_gtk:
				mime_type = gio.content_type_get_mime_type(gio.content_type_guess(path))
			else:
				mime_type, encoding = mimetypes.guess_type(path)
				if not mime_type:
					mime_type = "application/octet-stream"
			
			# If this mime type is text and the client does not accept is, send file as text/plain to
			# have it displayed
			if mime_type[:5] == "text/" and "accept" in self.request_headers and mime_type not in map(lambda x: x.strip().split(";")[0], self.request_headers["accept"].split(",")):
				mime_type = "text/plain; exact-type=" + mime_type

			file_stat = os.stat(path)
			# Check if-modified-since header
			modification_time = datetime.datetime.utcfromtimestamp(file_stat.st_mtime)
			if "if-modified-since" in self.request_headers:
				try:
					check_date = datetime.datetime.strptime(self.request_headers["if-modified-since"], "%a, %d %b %Y %H:%M:%S %Z")
					if (modification_time - check_date).seconds == 0:
						try:
							self.socket.send(self._headers("HTTP/1.1 304 Not modified", { "Last-Modified": format_timestamp(modification_time) }))
						except:
							self.handle_hup()
							return
						self.handle_finished()
						return
				except:
					pass
			# Take Range requests into account
			content_length = [ file_stat.st_size ]
			status = "HTTP/1.1 200 Ok"
			if "range" in self.request_headers:
				file_range_type, file_range_range = self.request_headers["range"].split("=", 1)
				file_range_range = file_range_range.split("-", 1)
				if file_range_type != "bytes" or len(file_range_range) != 2:
					try:
						self.socket.send(self._headers("HTTP/1.1 416 Requested range not satisfiable", {}))
					except:
						self.handle_hup()
						return
					self.handle_finished()
					return
				file_range_range[0] = int(file_range_range[0]) if file_range_range[0].isdigit() else 0
				file_range_range[1] = int(file_range_range[1]) if file_range_range[1].isdigit() else file_stat.st_size
				if file_range_range[0] < 0 or file_range_range[0] >= file_range_range[1] or file_range_range[1] > file_stat.st_size:
					try:
						self.socket.send(self._headers("HTTP/1.1 416 Requested range not satisfiable", {}))
					except:
						self.handle_hup()
						return
					self.handle_finished()
					return
				content_length[0] = file_range_range[1] - file_range_range[0]
				response_file.seek(file_range_range[0])
				status = "HTTP/1.1 206 Partial Content"
			response_headers = {
				"Content-Length": content_length[0],
				"Last-Modified": format_timestamp(modification_time),
				"Content-Type": mime_type
			}
			try:
				self.socket.send(self._headers(status, response_headers))
			except:
				self.handle_hup()
				return
			cache = StringIO.StringIO()
			def send_data():
				data = cache.read(1024 * 512)
				if not data:
					to_read = 10 * 1024 ** 2 if content_length[0] > 10 * 1024 ** 2 else content_length[0]
					content_length[0] -= to_read
					cache.truncate(0)
					data = response_file.read(to_read)
					cache.write(data)
					cache.seek(0)
					data = cache.read(1024 * 512)
				if not data:
					self.handle_finished()
					return
				try:
					# TODO
					self.socket.send(data)
				except:
					self.handle_hup()
					return
			if self.request_type == "HEAD":
				self.handle_finished()
				return
			self.event_ids.append(glib.io_add_watch(self.socket, glib.IO_OUT, lambda fd, cond: send_data() or True))
		else:
			self.reply_error(404)

	# Execute a CGI script
	def handle_cgi(self, argv):
		environ = os.environ.copy()
		environ.update({
			"SERVER_SOFTWARE": "ihttpd",
			"SERVER_NAME": self.request_headers["host"] if "host" in self.request_headers else "", # TODO Php does not like that?!
			"GATEWAY_INTERFACE": "CGI/1.1",
			"SERVER_PROTOCOL": "HTTP/1.1",
			"SERVER_PORT": str(server_port),
			"REQUEST_METHOD": self.request_type,
			"QUERY_STRING": self.request_query,
			"SCRIPT_NAME": self.request_file,
			"PATH_INFO": self.request_file,
			"REQUEST_URI": self.original_request_uri,
			"PATH_TRANSLATED": os.path.abspath(os.path.join(os.getcwd(), "." + self.request_file)),
			"REMOTE_ADDR": self.socket.getpeername()[0],
			"CONTENT_TYPE": self.request_headers["content-type"] if "content-type" in self.request_headers else "",
			"CONTENT_LENGTH": str(self.request_headers["content-length"]) if "content-length" in self.request_headers else "0"
		})
		for header in self.request_headers:
			environ["HTTP_%s" % header.upper().replace("-", "_")] = self.request_headers[header]
		def pre_exec_handler():
			# Ignore interrupt signal
			signal.signal(signal.SIGINT, signal.SIG_IGN)
		self.cgi_sent_header = ""
		def send_data():
			sys.stdout.flush()
			data = self.cgi_process.stdout.read(1024 * 512)
			sys.stdout.flush()
			if data == "":
				# Does not mean anything: Non-Blocking IO..
				return True
			if type(self.cgi_sent_header) is str:
				self.cgi_sent_header += data
				if "\r\n\r\n" in self.cgi_sent_header:
					response_headers, data = self.cgi_sent_header.split("\r\n\r\n", 1)
					try:
						self.socket.send(self._headers("HTTP/1.1 200 Ok", response_headers))
					except:
						self.handle_hup()
						return
					self.cgi_sent_header = True
				elif "\n\n" in self.cgi_sent_header:
					response_headers, data = self.cgi_sent_header.split("\n\n", 1)
					try:
						self.socket.send(self._headers("HTTP/1.1 200 Ok", response_headers))
					except:
						self.handle_hup()
						return
					self.cgi_sent_header = True
				else:
					return True
			try:
				if self.do_chunk:
					if len(data) == 0:
						return True
					self.socket.send(hex(len(data))[2:] + "\r\n")
				# TODO Make this non-blocking?!
				self.socket.send(data)
				if self.do_chunk:
					self.socket.send("\r\n")
			except:
				self.handle_hup()
				return
			if self.cgi_process.poll() != None:
				if self.do_chunk:
					self.socket.send("0\r\n\r\n")
					self.do_chunk = False
				self.handle_finished()
			return True
		def child_terminated():
			if self.do_chunk:
				self.socket.send("0\r\n\r\n")
				self.do_chunk = False
			self.handle_finished()
		self.cgi_process = subprocess.Popen(argv, close_fds=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=environ, preexec_fn=pre_exec_handler)
		fcntl.fcntl(self.cgi_process.stdout.fileno(), fcntl.F_SETFL, fcntl.fcntl(self.cgi_process.stdout.fileno(), fcntl.F_GETFL) | os.O_NONBLOCK)
		self.event_ids.append(glib.child_watch_add(self.cgi_process.pid, lambda pid, cond: child_terminated() or False))
		self.event_ids.append(glib.io_add_watch(self.cgi_process.stdout, glib.IO_IN | glib.IO_HUP | glib.IO_ERR, lambda fd, cond: send_data() or True))

	# Generate an error message
	def reply_error(self, err_no = 500):
		end_connection = False
		if err_no == 500:
			err_str = "Internal server error"
			end_connection = True
		elif err_no == 501:
			err_str = "Not implemented"
			end_connection = True
		elif err_no == 404:
			err_str = "Not found"
		elif err_no == 400:
			err_str = "Bad request"
			end_connection = True
		elif err_no == 408:
			err_str = "Request Time-out"
			end_connection = True
		elif err_no == 507:
			err_str = "Insufficient Storage"
		else:
			err_str = "Generic error"
		if end_connection:
			self.allow_keep_alive = False
		try:
			error_message = "<!DOCTYPE HTML>" + self._gen_head("Failed to handle your request") + \
				"<body><h1>Failed to handle your request</h1><p>" + err_str + "</p>"
			headers = { "Content-Type": "text/html; charset=utf8", "Content-Length": len(error_message)}
			self.socket.send(self._headers("HTTP/1.1 %d %s" % (err_no, err_str), headers) + error_message)
		except:
			self.handle_hup()
			return
		if not end_connection:
			self.handle_finished()
		else:
			self.handle_hup()

	# Reset the state when a request was processed
	def handle_finished(self):
		if self.do_chunk:
			self.socket.send("0\r\n\r\n")
			self.do_chunk = False
		if not self.allow_keep_alive:
			self.handle_hup()
		else:
			# Clean up
			if self.timeout_id != False:
				glib.source_remove(self.timeout_id)
			if self.cgi_process:
				try:
					self.cgi_process.terminate()
				except:
					pass
			for eid in self.event_ids:
				glib.source_remove(eid)
			# Reset
			self._restart_handlers(30)
			# Check if there is data to process
			if self.data_cache:
				self.handle_incoming(False)

	# Close the connection
	def handle_hup(self):
		Connection.instances -= 1
		if self.timeout_id != False:
			glib.source_remove(self.timeout_id)
		if self.cgi_process:
			try:
				self.cgi_process.terminate()
			except:
				pass
		self.socket.close()
		for eid in self.event_ids:
			glib.source_remove(eid)
		del self

# Trap sigint
main_loop = glib.MainLoop()
termination_requested = 0
def terminate_server(signum, frame):
	global termination_requested
	if termination_requested == 1:
		main_loop.quit()
		termination_requested = 2
		return
	elif termination_requested == 2:
		os.killpg(0, signal.SIGTERM)
		sys.exit(0)
	termination_requested = 1
	if Connection.instances > 0:
		print "\rReceived signal. Waiting for remaining connections to close.."
		print "Send again to force quit"
		server_socket.close()
		def watch():
			if Connection.instances == 0:
				print "\033[2A\033[J", # Remove those three lines above
				sys.exit(0)
			return True
		glib.idle_add(watch)
	else:
		main_loop.quit()
		termination_requested = 2

signal.signal(signal.SIGINT, terminate_server)
signal.signal(signal.SIGTERM, terminate_server)

# Create server socket
server_socket = socket.socket()
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_port = int(sys.argv[1]) if len(sys.argv) > 1 else 1234
while 1:
	try:
		server_socket.bind(("", server_port))
		break
	except:
		server_port += 1
print "Starting HTTP server on port %d" % server_port
server_socket.listen(5)
def create_connection():
	# There is a new incomming connection
	socket, ip = server_socket.accept()
	Connection(socket, ip)
glib.io_add_watch(server_socket, glib.IO_IN, lambda fd, cond: create_connection() or True)
main_loop.run()
# When the main loop has been left, kill all remaining children
os.killpg(0, signal.SIGTERM)
