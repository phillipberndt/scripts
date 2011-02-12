#!/usr/bin/python
import SocketServer
import sys
import socket
import os
import threading
import getopt

try:
	import dbus
	import avahi
	has_avahi = True
except:
	has_avahi = False
	

_socket = socket
_pasv_ports = {}
_portmap_lock = threading.Lock()
def acquirePort():
	_portmap_lock.acquire()
	usePort = 0
	for port, active in _pasv_ports.items():
		if active == False:
			usePort = port
			break
	if usePort in _pasv_ports:
		_pasv_ports[usePort] = True
	_portmap_lock.release()
	return usePort

class FTPHandler(SocketServer.StreamRequestHandler):
	def build_data(self):
		if self.connect_to == "PASV":
			srv = socket.socket()
			srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			srv.bind(('', self.pasv_port))
			srv.listen(1)
			data = srv.accept()[0]
			srv.shutdown(socket.SHUT_RDWR)
			srv.close()
			del srv
			return data
		else:
			data = socket.socket()
			data.connect(self.connect_to)
			return data
	data_socket = False
	def finish(self):
		if self.pasv_port != 0:
			_pasv_ports[self.pasv_port] = False
	def handle(self):
		print "Connection from %s" % self.connection.getpeername()[0]
		self.wfile.write("200 Hello out there\r\n")
		self.pasv_port = acquirePort()
		debug("Using port %d for passive ftp " % self.pasv_port)
		self.path = "/"
		self.rest = 0
		self.type = "I"
		self.renameFrom = None
		self.login = False
		while True:
			try:
				line = self.rfile.readline().strip().split()
			except:
				# Connection lost
				break
			if debug_mode:
				print "Received command: ", line
				try:
					arg = " ".join(line[1:]).replace('"', '')
					pwd = os.getcwd()
					if arg[0] == "/":
						newpath = os.path.abspath(pwd + arg)
					else:
						newpath = os.path.abspath(pwd + "/" + self.path + "/" + arg)
					print " Interpreted as file ", newpath
				except:
					pass
			if not line:
				break
			# Allow pre login
			if line[0] == "SYST":
				self.wfile.write("215 UNIX Type: L8\r\n")
				continue
			elif line[0] == "FEAT":
				self.wfile.write("211-Features:\r\nUTF8\r\nPASV\r\n211 End\r\n")
				continue
			elif line[0] == "NOOP":
				self.wfile.write("200 Pong\r\n")
				continue
			# Login
			if require_login and self.login != 2:
				if line[0] == "USER" and line[1] == require_login[0] and self.login == False:
					self.login = 1
					self.wfile.write("331 Ok\r\n")
					continue
				if line[0] == "USER":
					self.wfile.write("331 Ok\r\n")
					continue
				elif line[0] == "PASS" and len(line) > 1 and line[1] == require_login[1] and self.login == 1:
					self.login = 2
					self.wfile.write("200 Ok\r\n")
					continue
				self.wfile.write("530 Bah. Wrong. Authenticate yourself!\r\n")
				continue
			# Post login
			if line[0] == "USER" or line[0] == "PASS":
				self.wfile.write("230 Ill accept whatever you say\r\n")
			elif line[0] == "PORT":
				data = line[1].split(',')
				if len(data) != 6:
					self.wfile.write("500 Oops\r\n")
				else:
					ip = ".".join(data[0:4])
					port = (int(data[4]) << 8) + int(data[5])
					self.connect_to = (ip, port)
					self.wfile.write("200 Ok Ill connect to %s:%d\r\n" % (ip, port))
			elif line[0] == "PASV":
				if self.pasv_port == 0:
					self.wfile.write("425 Out of resources, sorry\r\n")
				else:
					if my_ip:
						the_ip = my_ip
					else:
						the_ip = self.connection.getsockname()[0]
					self.wfile.write("227 Entering passive mode (%s,%d,%d)\r\n" % (",".join(the_ip.split(".")),
						(self.pasv_port & 0xFF00) >> 8, (self.pasv_port & 0x00FF)))
					self.connect_to = "PASV"
					try:
						self.data_socket = self.build_data()
					except _socket.error:
						debug("Failed to build data connection")
						self.wfile.write("425 Failed to build data connection\r\n")
						continue
			elif line[0] == "QUIT":
				self.wfile.write("200 Bye\r\n")
				self.wfile.close()
				break
			elif line[0] == "RNFR":
				if not allow_store:
					self.wfile.write("550 Naa. Not here.\r\n")
					continue
				arg = " ".join(line[1:]).replace('"', '')
				pwd = os.getcwd()
				if arg[0] == "/":
					newpath = os.path.abspath(pwd + arg)
				else:
					newpath = os.path.abspath(pwd + "/" + self.path + "/" + arg)
				if newpath[0:len(pwd)] != pwd:
					self.wfile.write("553 You just tried to leave root. I cant let you do that\r\n")
				elif not os.access(newpath, os.F_OK):
					self.wfile.write("550 Not found\r\n")
					continue
				else:
					self.renameFrom = newpath
					self.wfile.write("350 Ok. To which file?\r\n")
			elif line[0] == "RNTO":
				if not allow_store:
					self.wfile.write("550 Naa. Not here.\r\n")
					continue
				if not self.renameFrom:
					self.wfile.write("500 Specify RNFR first\r\n")
					continue
				arg = " ".join(line[1:]).replace('"', '')
				pwd = os.getcwd()
				if arg[0] == "/":
					newpath = os.path.abspath(pwd + arg)
				else:
					newpath = os.path.abspath(pwd + "/" + self.path + "/" + arg)
				if newpath[0:len(pwd)] != pwd:
					self.wfile.write("553 You just tried to leave root. I cant let you do that\r\n")
				else:
					debug("Renamed " + self.renameFrom + " to " + newpath)
					os.rename(self.renameFrom, newpath)
					self.renameFrom = None
					self.wfile.write("250 Ok\r\n")
			elif line[0] == "DELE":
				if not allow_store:
					self.wfile.write("550 Naa. Not here.\r\n")
					continue
				arg = " ".join(line[1:]).replace('"', '')
				pwd = os.getcwd()
				if arg[0] == "/":
					newpath = os.path.abspath(pwd + arg)
				else:
					newpath = os.path.abspath(pwd + "/" + self.path + "/" + arg)
				if newpath[0:len(pwd)] != pwd:
					self.wfile.write("553 You just tried to leave root. I cant let you do that\r\n")
				else:
					os.unlink(newpath)
					self.wfile.write("250 Ok\r\n")
					debug("Removed file " + newpath)
			elif line[0] == "SITE":
				if not allow_store:
					self.wfile.write("550 Naa. Not here.\r\n")
					continue
				if line[1] != "CHMOD":
					self.wfile.write("500 I dont know anything but chmod\r\n")
					continue
				mode = line[2]
				arg = " ".join(line[3:]).replace('"', '')
				pwd = os.getcwd()
				if arg[0] == "/":
					newpath = os.path.abspath(pwd + arg)
				else:
					newpath = os.path.abspath(pwd + "/" + self.path + "/" + arg)
				if newpath[0:len(pwd)] != pwd:
					self.wfile.write("553 You just tried to leave root. I cant let you do that\r\n")
				elif not os.access(newpath, os.F_OK):
					self.wfile.write("550 Not found\r\n")
					continue
				else:
					os.chmod(newpath, int(mode, 8))
					self.wfile.write("200 Ok\r\n")
			elif line[0] == "CWD":
				if line[1] == "/":
					self.path = "/"
					self.wfile.write("200 Ok\r\n")
					continue
				arg = " ".join(line[1:]).replace('"', '')
				pwd = os.getcwd()
				if arg[0] == "/":
					newpath = os.path.abspath(pwd + arg)
				else:
					newpath = os.path.abspath(pwd + "/" + self.path + "/" + arg)
				if newpath[0:len(pwd)] != pwd:
					self.wfile.write("553 You just tried to leave root. I cant let you do that\r\n")
				elif not os.access(newpath, os.F_OK):
					self.wfile.write("550 Not found\r\n")
					continue
				else:
					self.path = newpath[len(pwd):]
					self.wfile.write("200 Ok\r\n")
			elif line[0] == "CDUP":
				pwd = os.getcwd()
				newpath = os.path.abspath(pwd + "/" + self.path + "/..")
				if newpath[0:len(pwd)] != pwd:
					self.wfile.write("553 You just tried to leave root. I cant let you do that\r\n")
				else:
					self.path = newpath[len(pwd):]
					self.wfile.write("200 Ok\r\n")
			elif line[0] == "PWD":
				self.wfile.write("257 \"%s\"\r\n" % self.path)
			elif line[0] == "TYPE":
				self.type = line[1]
				self.wfile.write("200 Ok\r\n")
			elif line[0] == "REST":
				self.rest = abs(int(line[1]))
				self.wfile.write("350 Restarting at %d. Send STORE or RETRIEVE to start file transfer\r\n" % self.rest)
			elif line[0] == "RMD":
				if not allow_store:
					self.wfile.write("550 Naa. Not here.\r\n")
					continue
				arg = " ".join(line[1:]).replace('"', '')
				pwd = os.getcwd()
				if arg[0] == "/":
					newpath = os.path.abspath(pwd + arg)
				else:
					newpath = os.path.abspath(pwd + "/" + self.path + "/" + arg)
				if newpath[0:len(pwd)] != pwd:
					self.wfile.write("553 You just tried to leave root. I cant let you do that\r\n")
					continue
				else:
					try:
						os.rmdir(newpath)
						debug("Removed directory %s" % newpath)
						self.wfile.write("200 Ok\r\n")
					except:
						self.wfile.write("400 Failure\r\n")
			elif line[0] == "MKD":
				if not allow_store:
					self.wfile.write("550 Naa. Not here.\r\n")
					continue
				arg = " ".join(line[1:]).replace('"', '')
				pwd = os.getcwd()
				if arg[0] == "/":
					newpath = os.path.abspath(pwd + arg)
				else:
					newpath = os.path.abspath(pwd + "/" + self.path + "/" + arg)
				if newpath[0:len(pwd)] != pwd:
					self.wfile.write("553 You just tried to leave root. I cant let you do that\r\n")
					continue
				else:
					try:
						os.mkdir(newpath)
						self.wfile.write("257 Ok\r\n")
						debug("Made dir " + newpath)
					except:
						self.wfile.write("400 Failure\r\n")
			elif line[0] == "STOR" or line[0] == "APPE":
				arg = " ".join(line[1:]).replace('"', '')
				pwd = os.getcwd()
				if arg[0] == "/":
					newpath = os.path.abspath(pwd + arg)
				else:
					newpath = os.path.abspath(pwd + "/" + self.path + "/" + arg)
				if newpath[0:len(pwd)] != pwd:
					self.wfile.write("553 You just tried to leave root. I cant let you do that\r\n")
					continue
				if not allow_store:
					self.wfile.write("550 Naa. Not here.\r\n")
					continue
				try:
					if self.data_socket:
						socket = self.data_socket
						self.data_socket = False
					else:
						socket = self.build_data()
				except _socket.error:
					self.wfile.write("425 Failed to build data connection\r\n")
					continue
				writeto = open(newpath, "w" if line[0] == "STOR" else "a")
				if line[0] == "STOR":
					writeto.truncate(self.rest)
					writeto.seek(self.rest)
					self.rest = 0
				self.wfile.write("150 Here we go\r\n")
				print "Receiving " + newpath
				
				while True:
					data = socket.recv(1024)
					if self.type == "A":
						if len(data) > 0 and data[-1] == "r": data = data + socket.recv(1)
						data = data.replace("\r\n", "\n")
					if data == "":
						break
					writeto.write(data)
				debug("Done")

				writeto.close()				
				socket.close()
				self.wfile.write("226 Ok.\r\n")
			elif line[0] == "SIZE":
				arg = " ".join(line[1:]).replace('"', '')
				pwd = os.getcwd()
				if arg[0] == "/":
					newpath = os.path.abspath(pwd + arg)
				else:
					newpath = os.path.abspath(pwd + "/" + self.path + "/" + arg)
				if newpath[0:len(pwd)] != pwd:
					self.wfile.write("553 You just tried to leave root. I cant let you do that\r\n")
					continue
				elif not os.access(newpath, os.F_OK):
					self.wfile.write("550 Not found\r\n")
					continue
				self.wfile.write("213 %d\r\n" % os.stat(newpath).st_size)
			elif line[0] == "RETR":
				arg = " ".join(line[1:]).replace('"', '')
				pwd = os.getcwd()
				if arg[0] == "/":
					newpath = os.path.abspath(pwd + arg)
				else:
					newpath = os.path.abspath(pwd + "/" + self.path + "/" + arg)
				if newpath[0:len(pwd)] != pwd:
					self.wfile.write("553 You just tried to leave root. I cant let you do that\r\n")
					continue
				elif not os.access(newpath, os.F_OK):
					self.wfile.write("550 Not found\r\n")
					continue
				print "Sending " + newpath

				try:
					if self.data_socket:
						socket = self.data_socket
						self.data_socket = False
					else:
						socket = self.build_data()
				except _socket.error:
					debug("Failed to build data connection")
					self.wfile.write("425 Failed to build data connection\r\n")
					continue
				self.wfile.write("150 Opening data connection for %s (%d bytes)\r\n" % (
						os.path.basename(newpath),
						os.stat(newpath).st_size
					))
				fcont = open(newpath)
				fcont.seek(self.rest)
				self.rest = 0
				while True:
					content = fcont.read(1024)
					if self.type == "A":
						content = content.replace("\n", "\r\n")
					if content == "": break
					try:
						socket.send(content)
					except _socket.error:
						# Connection lost
						break
				fcont.close()
				socket.close()
				self.wfile.write("226 Ok what now?\r\n")
			elif line[0] == "LIST":
				try:
					if self.data_socket:
						socket = self.data_socket
						self.data_socket = False
					else:
						socket = self.build_data()
				except _socket.error:
					self.wfile.write("425 Failed to build data connection\r\n")
					continue
				self.wfile.write("150 Here we go\r\n")
				args = ""
				if len(line) > 1 and line[1] == "-a":
					args = "a"
				os.environ["LC_ALL"] = "en_US.utf8"
				socket.send(os.popen("ls -ln%s --time-style='+%%b %%d %%Y' .%r" %
					(args, self.path)).read().replace("\n", "\r\n"))
				socket.close()
				self.wfile.write("226 Ok what now?\r\n")
			else:
				self.wfile.write("500 I dont know about that as Im dumb (You said: %s)\r\n" % line[0])

					
my_ip = ""
allow_store = False
baseport = 12000
trange = 20
add = 0
debug_mode = False
daemon_mode = False
require_login = False
use_avahi = False

try:
	(options, rest) = getopt.getopt(sys.argv[1:], "sp:r:h:dDl:a")
except:
	print "iftpd - Instant FTPD"
	print "Copyright (c) 2009-2011, Phillip Berndt"
	print
	print "Creates a FTP daemon in ./"
	print
	print "Syntax: iftpd -s -p <port> -r <range> -h <host>"
	print 
	print " -s            Allow users to modify data"
	print " -p            Listen on port <port>          (Default: 12000)"
	print " -r            Use <port> - <port> + <range>"
	print "                for passive mode FTP          (Default: 20)"
	print " -h            Send <host> for passive mode"
	print "                connection host"
	print " -d            Debug mode"
	print " -D            Daemon mode"
	print " -l            Require <user>:<pass> login    (Default: Allow all)"
	print " -a            Announce service to local network via Avahi"
	print
	sys.exit(1)

for option, arg in options:
	if option == "-s":
		print "WARNING: Activating store mode"
		allow_store = True
	if option == "-p":
		baseport = int(arg)
	if option == "-r":
		trange = int(arg)
	if option == "-h":
		my_ip = socket.gethostbyname(arg)
	if option == "-d":
		debug_mode = True
	if option == "-D":
		daemon_mode = True
	if option == "-l":
		require_login = arg.split(":", 2)
	if option == "-a":
		if not has_avahi:
			print "python-dbus or python-avahi not available. Ignoring -a."
		else:
			use_avahi = True

if debug_mode:
	def debug(string):
		print string
else:
	def debug(string):
		pass

while True:
	try:
		server = SocketServer.ThreadingTCPServer(('', baseport + add), FTPHandler, False)
		server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server.server_bind()
		server.server_activate()
		print "Serving on port %d" % (baseport + add)
	except:
		add = add + 1
		if add > 20:
			print "Failed to find a port :/"
			sys.exit(1)
		continue
	break
_pasv_ports = dict(zip(range(baseport + add + 1, baseport + add + trange + 1), [ False ] * trange))
for port in _pasv_ports.keys():
	srv = socket.socket()
	srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	try:
		srv.bind(('', port))
		srv.close()
		del srv
	except _socket.error:
		del _pasv_ports[port]
		del srv
print "Using ports %d to %d for passive mode (%d are useable)" % (baseport + 1 + add, baseport + 1 + add + trange, len(_pasv_ports))
if use_avahi:
	debug("Announcing service via Avahi")
	bus = dbus.SystemBus()
	dbserver = dbus.Interface(bus.get_object(avahi.DBUS_NAME, avahi.DBUS_PATH_SERVER), avahi.DBUS_INTERFACE_SERVER)
	group = dbus.Interface(bus.get_object(avahi.DBUS_NAME, dbserver.EntryGroupNew()), avahi.DBUS_INTERFACE_ENTRY_GROUP)
	group.AddService(avahi.IF_UNSPEC, avahi.PROTO_UNSPEC, dbus.UInt32(0), "iftpd on " + socket.gethostname(), "_ftp._tcp", "", "", dbus.UInt16(baseport + add), "")
	group.Commit()

if daemon_mode:
	debug("Switching to daemon mode")
	if os.fork() != 0:
		os._exit(0)
	os.setsid()
	if os.fork() != 0:
		os._exit(0)
	for i in range(3): os.close(i)
	os.open(os.devnull if hasattr(os, "devnull") else "/dev/null", os.O_RDWR)
	os.dup2(0, 1)
	os.dup2(0, 2)
try:
	server.serve_forever()
except KeyboardInterrupt:
	if use_avahi:
		group.Reset()
	os._exit(0)
finally:
	if use_avahi:
		group.Reset()
	
