#!/usr/bin/env python
# encoding: utf-8
#
# Copy an already installed debian package into a user directory (p.e. for
# setting up a chroot)
#
import getopt
import os
import shutil
import sys

def files(package, source):
	return ( x.strip() for x in os.popen("dpkg --admindir=" + source + "/var/lib/dpkg -L " + package).readlines() )

def install(file, source, target_base):
	real_file = os.path.join(source, "." + file)

	if not os.path.isfile(real_file):
		return
	target = os.path.join(target_base, "./" + file)
	try:
		os.makedirs(os.path.dirname(target))
	except:
		pass
	if not os.access(target, os.F_OK):
		shutil.copy2(real_file, target)

def dependencies(package, source):
	return ( x[x.find(": ") + 2:].strip().replace("<", "").replace(">", "") for x in os.popen("apt-cache -o RootDir=" + source + " depends " + package).readlines() if "Depends" in x )

_deps = []

def _install_single_package(package, source, target_base):
	global _deps
	for dep in dependencies(package, source):
		if dep in _deps:
			continue
		_deps += [ dep ]
		_install_single_package(dep, source, target_base)
	print "Installing", package, "..."
	for file in files(package, source):
		install(file, source, target_base)

def install_packages(packages, source, target_base):
	global _deps
	_deps = []
	if type(packages) is str:
		packages = [ packages ]
	for package in packages:
		_install_single_package(package, source, target_base)

if __name__ == '__main__':
	try:
		args, params = getopt.getopt(sys.argv[1:], "s:d:")
	except:
		print "Syntax: add_package [-s source] [-d root] package(s)..."
		sys.exit(0)

	args = dict(args)
	if "-d" in args:
		target_base = args["-d"]
	else:
		target_base = "./"
	if "-s" in args:
		source = args["-s"]
	else:
		source = "/"

	install_packages(params, source, target_base)
