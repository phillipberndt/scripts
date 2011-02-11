#!/usr/bin/python
import glib
import socket
import sys
import mimetypes
import os
import subprocess
import signal
import StringIO
import datetime
import re

# Define CGI handlers
cgi_handlers = {
	"php": "/usr/bin/php5-cgi",
	"pl": "/usr/bin/perl"
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
				rule_match = re.match("\s*RewriteRule\s+(\S+)\s+(\S+).+", line)
				if rule_match:
					match_against = path[len(basedir):] if path[:len(basedir)] == basedir else path
					if match_against and match_against[0] == "/":
						match_against = match_against[1:]
					if re.match(rule_match.group(1), match_against):
						path = new_path + re.sub(rule_match.group(1), rule_match.group(2).replace("$", "\\"), match_against)
	return path

# Format a timestamp
def format_timestamp(date_object):
	return date_object.strftime("%a, %d %b %Y %H:%M:%S UTC")

# Format HTTP Headers for output
def headers(status, headers):
	if type(headers) is str:
		headers = headers.replace("\r\n", "\n")
		if headers[:7] == "HTTP/1.":
			status, headers = headers.split("\n", 1)
		headers = dict(( (y[0].lower(), y[1]) for y in ( x.split(":", 1) for x in headers.split("\n") )))
		if "status" in headers:
			status = headers["status"]
			del headers["status"]
	else:
		headers = dict(( (str(x[0]).lower(), str(x[1])) for x in headers.items() ))
	if "date" not in headers:
		headers["date"] = format_timestamp(datetime.datetime.utcnow())
	headers["connection"] = "Close"
	return status + "\r\n" + "\r\n".join(( str(x[0]).capitalize() + ": " + str(x[1]) for x in headers.items() )) + "\r\n\r\n"


# Class for connection handling
class Connection(object):
	def __str__(self):
		return ":".join(map(str, self.remote_addr))

	def __init__(self, socket, ip):
		self.socket = socket
		self.socket_fileno = socket.fileno()
		self.remote_addr = ip
		self.state = 1
		self.request_headers = {}
		self.request_type = ""
		self.request_uri = ""
		self.data_cache = ""
		self.cgi_process = False
		self.event_ids = []
		self.hup_done = False
		self.timeout_id = False

		self.event_ids.append(glib.io_add_watch(self.socket, glib.IO_IN, lambda fd, cond: self.handle_incoming() or True))
		self.event_ids.append(glib.io_add_watch(self.socket, glib.IO_HUP, lambda fd, cond: self.handle_hup() or True))
		self.timeout_id = glib.timeout_add(30000, self.handle_timeout)
	
	def handle_timeout(self):
		self.handle_hup()	

	def handle_incoming(self):
		try:
			self.data_cache += self.socket.recv(1024)
		except:
			self.handle_hup()
		if self.data_cache == "":
			# HUP
			self.handle_hup()
			return
		while self.state < 3 and "\n" in self.data_cache:
			data = self.data_cache.split("\n", 1)
			data, self.data_cache = data
			if data and data[-1] == "\r": data = data[:-1]
			if self.state == 1: # Awaiting first line of request header
				request = data.split()
				if len(request) != 3 or (request[2] != "HTTP/1.1" and request[2] != "HTTP/1.0"):
					self.reply_error()
					return
				self.request_type = request[0]
				self.request_uri = request[1]
				self.original_request_uri = re.sub("%([A-F0-9]{2})", lambda x: chr(int(x.group(1), 16)), self.request_uri)

				# URL rewriting and path mapping
				path = os.path.abspath(os.path.join(os.getcwd(), "./" + self.original_request_uri))
				# TODO URL rewriting could also be wanted if the file exists..
				if not os.access(path[:path.find("?") if path.find("?") > -1 else len(path)], os.F_OK):
					path = rewrite_url(path)
				if path[:len(os.getcwd())] != os.getcwd():
					self.reply_error()
					return
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
					# Finished. Handle request
					self.state = 3
					glib.source_remove(self.timeout_id)
					self.timeout_id = False
					self.handle_request()
					break
				header = data.split(":", 1)
				if len(header) != 2:
					self.reply_error()
					return
				self.request_headers[header[0].lower()] = header[1].strip()
		if self.state == 3:
			# Handle POST request data. This does not require line caching
			if self.cgi_process:
				self.cgi_process.stdin.write(self.data_cache)
				self.data_cache = ""
		return True

	def handle_request(self):
		print "[%s] %s" % (self, self.request_uri)
		path = os.path.abspath(os.path.join(os.getcwd(), "./" + self.request_file))
		if os.path.isdir(path):
			# Search for directory index
			for index in ("index.html", "index.php", "index.pl", "index"):
				new_path = os.path.join(path, index)
				if os.access(new_path, os.F_OK):
					self.socket.send(headers("HTTP/1.1 301 Permanently redirected", { "Location": os.path.join(self.request_file, index) }))
					self.handle_hup()
		if os.path.isdir(path):
			# This is a directory.
			# Redirect to a URL ending in a slash
			if self.request_file and self.request_file[-1] != "/":
				self.socket.send(headers("HTTP/1.1 301 Permanently redirected", { "Location": self.request_file + "/" }))
				self.handle_hup()
				return
			# Generate a directory listing
			output_str = "<!DOCTYPE HTML><body><h1>Directory Listing for %s</h1><ul>" % (self.request_file.replace("<", "&lt;"))
			for my_file in ( x.replace('"', "&quot;").replace("<", "&amp;") for x in os.listdir(path) if x[0] != "." ):
				if os.path.isdir(os.path.join(path, my_file)):
					my_file += "/"
				output_str += '<li><a href="%s">%s</a></li>' % (my_file, my_file)
			output_str += "</ul></body>"
			output = StringIO.StringIO(output_str)
			def send_data():
				write = output.read(1024 * 512)
				if not write:
					self.handle_hup()
					return
				self.socket.send(write)
			response_headers = {
				"Content-Length": len(output_str),
				"Content-Type": "text/html; charset=utf-8"
			}
			self.socket.send(headers("HTTP/1.1 200 Ok", response_headers)) 
			if self.request_type == "HEAD":
				self.handle_hup()
				return
			self.event_ids.append(glib.io_add_watch(self.socket, glib.IO_OUT, lambda fd, cond: send_data() or True))
		elif os.access(path, os.F_OK):
			# File exists.
			# Handle as CGI if applicable
			extension = os.path.splitext(path)[1][1:]
			if extension in cgi_handlers:
				self.handle_cgi(cgi_handlers[extension] + " '" + path.replace("'", r"\'") + "'")
				return
			# Send the file back to the user
			response_file = open(path, "r")
			mime_type, encoding = mimetypes.guess_type(path)
			if not mime_type:
				mime_type = "application/octet-stream"
			file_stat = os.stat(path)
			# Check if-modified-since header
			modification_time = datetime.datetime.utcfromtimestamp(file_stat.st_mtime)
			if "if-modified-since" in self.request_headers:
				try:
					check_date = datetime.datetime.strptime(self.request_headers["if-modified-since"], "%a, %d %b %Y %H:%M:%S %Z")
					if (modification_time - check_date).seconds == 0:
						self.socket.send(headers("HTTP/1.1 304 Not modified", { "Last-Modified": format_timestamp(modification_time) }))
						self.handle_hup()
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
					self.socket.send(headers("HTTP/1.1 416 Requested range not satisfiable", {}))
					self.handle_hup()
					return
				file_range_range[0] = int(file_range_range[0]) if file_range_range[0].isdigit() else 0
				file_range_range[1] = int(file_range_range[1]) if file_range_range[1].isdigit() else file_stat.st_size
				if file_range_range[0] < 0 or file_range_range[0] >= file_range_range[1] or file_range_range[1] > file_stat.st_size:
					self.socket.send(headers("HTTP/1.1 416 Requested range not satisfiable", {}))
					self.handle_hup()
					return
				content_length[0] = file_range_range[1] - file_range_range[0]
				response_file.seek(file_range_range[0])
				status = "HTTP/1.1 206 Partial Content"
			response_headers = {
				"Content-Length": content_length[0],
				"Last-Modified": format_timestamp(modification_time),
				"Content-Type": mime_type
			}
			self.socket.send(headers(status, response_headers))
			def send_data():
				to_read = 1024 * 512 if content_length[0] > 1024 * 512 else content_length[0]
				content_length[0] -= to_read
				data = response_file.read(to_read)
				if not data:
					self.handle_hup()
					return
				self.socket.send(data)
				if content_length[0] == 0:
					self.handle_hup()
					return
			if self.request_type == "HEAD":
				self.handle_hup()
				return
			self.event_ids.append(glib.io_add_watch(self.socket, glib.IO_OUT, lambda fd, cond: send_data() or True))
		else:
			self.reply_error(404)

	def handle_cgi(self, executable):
		environ = os.environ.copy()
		environ.update({
			"SERVER_SOFTWARE": "httpd",
			"SERVER_NAME": self.request_headers["host"] if "Host" in self.request_headers else "",
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
		self.cgi_process = subprocess.Popen(executable, close_fds=True, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=environ)
		self.cgi_sent_header = ""
		def send_data():
			data = self.cgi_process.stdout.read(1024 * 512)
			if type(self.cgi_sent_header) is str:
				self.cgi_sent_header += data
				if "\r\n\r\n" in data:
					response_headers, data = self.cgi_sent_header.split("\r\n\r\n", 1)
					self.socket.send(headers("HTTP/1.1 200 Ok", response_headers))
					self.cgi_sent_header = True
				elif "\n\n" in data:
					response_headers, data = self.cgi_sent_header.split("\r\n\r\n", 1)
					self.socket.send(headers("HTTP/1.1 200 Ok", response_headers))
					self.cgi_sent_header = True
				else:
					return True
			self.socket.send(data)
			if self.cgi_process.poll() != None:
				self.handle_hup()
			return True
		self.event_ids.append(glib.io_add_watch(self.cgi_process.stdout, glib.IO_IN | glib.IO_HUP | glib.IO_ERR, lambda fd, cond: send_data() or True))
		def child_terminated():
			self.handle_hup()
		self.event_ids.append(glib.child_watch_add(self.cgi_process.pid, lambda pid, cond: child_terminated() or False))

	def reply_error(self, err_no = 500):
		self.socket.send("HTTP/1.1 %d Internal server error\r\nContent-Type: text/plain\r\n\r\nFailed to handle your request." % err_no)
		self.handle_hup()

	def handle_hup(self):
		if self.hup_done:
			return
		self.hup_done = True
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
glib.MainLoop().run()
