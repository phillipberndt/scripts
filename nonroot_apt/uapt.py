#!/usr/bin/env python
# encoding: utf-8
# 
# User APT
#
# Use debian packages on (non-debian) distributions as a non-root user
#
try:
	import cPickle as pickle
except:
	import pickle
import bz2
import anydbm
import ctypes
import getopt
import glob
import gzip
import math
import os
import re
import sys
import tempfile
import urllib

# Helper functions
def download(url):
	handle, tmp = tempfile.mkstemp()
	os.close(handle)
	display_name = os.path.basename(url)
	def report(blocks_so_far, block_size, total_size):
		if total_size < 1:
			print "\r\033[2K%60s | %02.2f Mb" % (display_name, blocks_so_far * block_size / 1024. / 1024.),
			sys.stdout.flush()
		else:
			percent = min(1., blocks_so_far * block_size * 1. / total_size)
			print "\r\033[2K%60s | %s%s [%02.2f/%02.2f Mb]" % (display_name, "#" * int(math.floor(percent * 50)), "-" * int(math.ceil(50 - percent * 50)), blocks_so_far * block_size / 1024. / 1024., total_size / 1024. / 1024.),
			sys.stdout.flush()
	urllib.urlretrieve(url, tmp, report)
	print
	return tmp

def url_get(url):
	tmp = download(url)
	if url[-3:] == ".gz":
		try:
			contents = gzip.open(tmp).read()
		except:
			return ""
	else:
		contents = open(tmp).read()
	os.unlink(tmp)
	return contents

# Read command line arguments
try:
	opts, args = getopt.getopt(sys.argv[1:], "d:ugs:")
	oopts = dict(opts)
except:
	print "Usage: uapt [-g] [-d directory] [-u] [-s source -s source ..] <package(s)>"
	print " directory defaults to ~/.local"
	print " source defaults to sources.list or, if unavailable, `deb http://ftp.de.debian.org/debian/ wheezy main contrib non-free'"
	print "  sources are cached. New sources don't override old sources unless -u is given."
	print " use -u to update the sources, otherwise the cache is used."
	print " use -g to ignore globally fulfiled dependencies."
	sys.exit(1)

# Search for target directory
if "-d" in oopts:
	target = os.path.expanduser(oopts["-d"])
else:
	target = os.path.expanduser("~/.local")
if not os.path.isdir(target):
	print >> sys.stderr, "Target", target, "does not exist"
	sys.exit(1)

# Resource directory
uapt_dir = os.path.expanduser("~/.uapt")
if not os.path.isdir(uapt_dir):
	os.mkdir(uapt_dir)

# Read sources list
sources = [ line[1] for line in opts if line[0] == "-s" ]
auto_sources = False
if not sources:
	auto_sources = True
	if os.access("/etc/apt/sources.list", os.F_OK):
		sources = [ x.strip() for x in open("/etc/apt/sources.list").readlines() if x[:4] == "deb " ]
	elif os.access(uapt_dir + "sources", os.F_OK):
		sources = open(uapt_dir + "/sources").readlines()
	else:
		sources = [ "deb http://ftp.de.debian.org/debian/ wheezy main contrib non-free" ]

# Determine arch
arch_map = { "x86_64": "amd64", "x86": "i386" }
try:
	arch = arch_map[os.popen("uname -m").read().strip()]
except:
	print "Unknown arch, please configure manually in source-code. Only x86 64/32 are supported right now, sorry!"

# Fetch sources
do_update = "-u" in oopts or not os.access(uapt_dir + "/packages", os.F_OK) or not auto_sources
source_db = {}
if not auto_sources or not do_update:
	print "Loading database.."
	sys.stdout.flush()
	if os.access(uapt_dir + "/packages", os.F_OK):
		source_db = pickle.load(bz2.BZ2File(uapt_dir + "/packages", "r"))
	else:
		source_db = {}
if do_update:
	print "Updating sources database ..."
	for source in sources:
		try:
			source_db["uapt-sources"] += [ source.strip() ]
		except KeyError:
			source_db["uapt-sources"] = [ source.strip() ]
		source = source.strip().split()
		if source[0] != "deb":
			continue
		base = os.path.join(source[1], "dists", source[2])
		def handle_contents(component):
			if component:
				contents_url = os.path.join(base, component, "Contents-" + arch + ".gz")
			else:
				contents_url = os.path.join(base, "Contents-" + arch + ".gz")
			packages = {}
			header_done = False
			for line in url_get(contents_url).split("\n"):
				if not header_done:
					if line[0:4] == "FILE":
						header_done = True
					continue
				split = line.split()
				if len(split) == 0:
					continue
				the_file = " ".join(split[:-1])
				package = split[-1]
				try:
					packages[package].append(the_file)
				except KeyError:
					packages[package] = [ the_file ]
			for package in packages:
				if "/" in package:
					display_package = package[package.find("/")+1:]
				else:
					display_package = package
				source_db["contents-" + display_package] = "\n".join(packages[package])
			del packages
		print " ", base
		handle_contents("")
		for component in source[3:]:
			print " ", base, " ", component + ":"
			# Load contents file
			handle_contents(component)
			# Load packages file
			for packages_file_paths in ("binary-all", "binary-" + arch):
				packages_url = os.path.join(base, component, packages_file_paths, "Packages.gz")
				for package in url_get(packages_url).split("\n\n"):
					entries = {}
					last = None
					for x in package.split("\n"):
						if not x:
							continue
						if x[0] in " \t":
							entries[last] += x.strip()
						else:
							data = x.split(": ", 1)
							entries[data[0]] = data[1].strip()
							last = data[0]
					if not entries:
						continue
					package = entries["Package"]
					if "Provides" in entries:
						for provided in entries["Provides"].split(","):
							prov_key = "providers-" + provided.strip()
							try:
								source_db[prov_key] += "\n" + package
							except KeyError:
								source_db[prov_key] = package
					if "SHA1" in entries:
						source_db["source-" + package] = os.path.join(source[1], entries["Filename"]) + "|" + entries["SHA1"]
					else:
						source_db["source-" + package] = os.path.join(source[1], entries["Filename"])
					deps = ""
					deps_array = []
					if "Depends" in entries:
						deps_array += entries["Depends"].split(",")
					if "Pre-Depends" in entries:
						deps_array += entries["Pre-Depends"].split(",")
					for dep in deps_array:
						parts = []
						for part in dep.split("|"):
							if "(" in part:
								# Ignore version numbers for now
								part = part[:part.find("(")] + part[part.find(")") + 1:]
							if "[" in part:
								dep_arch = part[part.find("[") + 1:part.find("]")]
								part = part[:part.find("[")] + part[part.find("]") + 1:]
								# TODO We're missing stuff like linux-any here, see
								# http://www.debian.org/doc/debian-policy/ch-relationships.html#s-binarydeps
								if dep_arch[0] == "!":
									if arch == dep_arch:
										continue
								else:
									if arch != dep_arch:
										continue
							parts += [ part.strip() ]
						deps += "|".join(parts) + "\n"
					source_db["deps-" + package] = deps
	pickle.dump(source_db, bz2.BZ2File(uapt_dir + "/packages", "w"), pickle.HIGHEST_PROTOCOL)

# TODO Store source lines

# If no args are given, display some stats and exit
if not args:
	source_db["uapt-sources"] = list(set(source_db["uapt-sources"]))
	print "My database currently holds %d packages from the %d following sources:" % (len(filter(lambda x: x[:7] == "source-", source_db)), len(source_db["uapt-sources"]))
	print " - %s" % ("\n - ".join(source_db["uapt-sources"]))
	print
	print "Use uapt -h for help."
	print
	sys.exit(0)

# Select packages to install
install = []
for package in args:
	candidates = []
	for key in source_db:
		if key[:6] == "source" and package in key:
			candidates.append(key[7:])
	if len(candidates) == 1:
		package = candidates[0]
	if package not in candidates:
		if "providers-" + package in source_db:
			candidates = [ x.strip() for x in source_db["providers-" + package].split("\n") ]
			package = candidates[0]
		else:
			print package, "not found. Candidates are: ", ", ".join(candidates[:10])
			continue
	install += [ package ]
install_force = install[:]

# Resolve dependencies
_version_vodoo_libs = []
def _version_vodoo_read(config):
	global _version_vodoo_libs
	try:
		lines = open(config).readlines()
	except:
		return
	for line in lines:
		line = line.strip()
		if line[:8] == "include ":
			for file in glob.glob(line[8:]):
				_version_vodoo_read(file)
		elif os.path.isdir(line):
			_version_vodoo_libs += os.listdir(line)

def _version_vodoo_cmp(version1, version2):
	def normalize(v):
		return [int(x) for x in re.sub(r'(\.0+)*$','', v).split(".")]
	return cmp(normalize(version1), normalize(version2))

def _version_vodoo_ver(package):
	verstring = re.search("(^.+\.so)\.([0-9\.]+)$", package)
	if verstring:
		return [verstring.group(1), verstring.group(2)]
	verstring = re.search("(^.+)-([0-9\.]+).so$", package)
	if verstring:
		return [verstring.group(1), verstring.group(2)]
	return False

def version_vodoo(package):
	global _version_vodoo_libs
	if not _version_vodoo_libs:
		_version_vodoo_read("/etc/ld.so.conf")

	ver = _version_vodoo_ver(package)
	if not ver:
		return []
	base, p_version = ver
	def _filter(candidate):
		if base not in candidate:
			return False
		ver = _version_vodoo_ver(candidate)
		if not ver:
			return False
		c_base, c_version = ver
		return _version_vodoo_cmp(c_version, p_version) >= 0
	return filter(_filter, _version_vodoo_libs)

def is_installed(package):
	if package in install_force:
		return False
	if "contents-" + package not in source_db:
		print "[%20s] No source information" % (package)
		return False
	files = 0
	files_ok = 0
	missing = 0
	for p_file in source_db["contents-" + package].split("\n"):
		if any(( ignore in p_file for ignore in ("usr/share/doc", "usr/share/man", "usr/share/help") )):
			continue

		files += 1
		if ("-g" not in oopts and os.access(os.path.join("/", p_file), os.F_OK)) or os.access(os.path.join(target, p_file), os.F_OK):
			files_ok += 1
		else:
			if (p_file[:4] == "lib/" or "/lib" in p_file) and ".so" in p_file:
				# Try to load directly, also search for newer versions
				exists = False
				basename = os.path.basename(p_file)
				for version in version_vodoo(basename):
					try:
						ctypes.CDLL(version)
						exists = True
						print "[%20s] Use %-40s for %-40s" % (package, basename, version)
						break
					except:
						pass
				if exists:
					files_ok += 1
					continue
			missing += 1
			if missing < 5:
				print "[%20s] Missing %s" % (package, p_file)
			elif missing == 10:
				print "[%20s] (Further missing files listing suppressed)" % (package)
	return (files > 10 and files - files_ok < 5) or files_ok == files

did_deps = True
while did_deps:
	old_length = len(install)
	for package in install[:]:
		if "deps-" + package in source_db:
			for dep in source_db["deps-" + package].split("\n"):
				if not dep:
					continue
				alternatives = dep.split("|")
				if any(alternatives) in install:
					continue
				dep = alternatives[0]
				if "source-" + dep in source_db:
					install += [ dep ]
				elif "providers-" + dep in source_db:
					candidates = [ x.strip() for x in source_db["providers-" + dep].split("\n") ]
					install += [ candidates[0] ]
				else:
					print >> sys.stderr, "Package", dep, "unavailable."
					#sys.exit(1)
	install = list(set(install))
	did_deps = len(install) > old_length

for package in install:
	if not package:
		continue
	if "source-" + package not in source_db:
		print >> sys.stderr, "Package", package, "unavailable."
		#sys.exit(1)

# Install packages
downloads = []
for package in install:
	if not package:
		continue
	if not is_installed(package):
		downloads += [ source_db["source-" + package].split("|") ]

if downloads:
	downloads = dict(zip(range(len(downloads)), downloads))
	if os.system("which zenity >/dev/null 2>&1") == 0 and "DISPLAY" in os.environ:
		ids = os.popen('zenity --list --checklist --multiple --text="Choose packages" --column=Install --column=id --hide-column=2 --column=Package ' + 
			" ".join([ 'TRUE ' + str(key) + ' "' + val[0].replace('"', r'\"') + '"' for key, val in downloads.items() ])).read().split("|")
		use = {}
		for id in ids:
			if id:
				use[int(id)] = downloads[int(id)]
		downloads = use
	else:
		while True:
			print "I will install to", target, ":"
			print
			for i in range(len(downloads)):
				print " %02d) %s" % (i, downloads[i][0])
			print
			print "Any objections, Lady? [<number> to remove that package, <enter> to proceed]",
			cmd = raw_input().strip()
			if cmd.isdigit():
				if int(cmd) in downloads:
					print "Ok, %s removed. What now?" % (downloads[int(cmd)][0]),
					del downloads[int(cmd)]
			else:
				break
	downloads = downloads.values()
	print
	
if downloads:
	for file in downloads:
		tmp = download(file[0])
		if len(file) > 1:
			chksum = os.popen("sha1sum %s" % tmp).read().strip().split()[0]
			if chksum != file[1]:
				print "Warning: SHA1 mismatch!\nExpected: %s\n   Found: %s" % (file[1], chksum)
		dl_type = os.popen("ar t %s | grep data" % tmp).read().strip()
		if ".tar.xz" in dl_type or ".tar.lzma" in dl_type:
			c_flag = "--lzma"
		elif ".tar.gz" in dl_type:
			c_flag = "-z"
		elif ".tar.bz2" in dl_type:
			c_flag = "-j"
		else:
			print "Unknown ", dl_type
		if os.system("ar p %s %s | tar -x %s -C %s" % (tmp, dl_type, c_flag, target)) != 0:
			print "Warning: Unpacking failed."
		os.unlink(tmp)
