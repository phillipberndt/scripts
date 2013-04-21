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

def files(package):
	return ( x.strip() for x in os.popen("dpkg -L " + package).readlines() )

def install(file, target_base):
	if not os.path.isfile(file):
		return
	target = os.path.join(target_base, "./" + file)
	try:
		os.makedirs(os.path.dirname(target))
	except:
		pass
	if not os.access(target, os.F_OK):
		shutil.copy2(file, target)

def dependencies(package):
	return ( x[x.find(": ") + 2:].strip().replace("<", "").replace(">", "") for x in os.popen("apt-cache depends " + package).readlines() if "Depends" in x )

_deps = []

def _install_single_package(package, target_base):
	global _deps
	for dep in dependencies(package):
		if dep in _deps:
			continue
		_deps += [ dep ]
		_install_single_package(dep, target_base)
	print "Installing", package, "..."
	for file in files(package):
		install(file, target_base)

def install_packages(packages, target_base):
	global _deps
	_deps = []
	if type(packages) is str:
		packages = [ packages ]
	for package in packages:
		_install_single_package(package, target_base)

if __name__ == '__main__':
	try:
		args, params = getopt.getopt(sys.argv[1:], "d:")
	except:
		print "Syntax: add_package [-d root] package(s)..."
		sys.exit(0)

	if len(args) > 0:
		target_base = args[0][1]
	else:
		target_base = "./"

	install_packages(params, target_base)
