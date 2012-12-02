#!/usr/bin/env python
# encoding: utf-8
#
# Install a Debian package and an unsatisfied dependencies into a user directory
#
import getopt
import os
import sys
import time

try:
	(lopts, args) = getopt.getopt(sys.argv[1:], "d:qs:")
	opts = dict(lopts)
except:
	print "non-root apt-get\nCommand line switches:\n"
	print "  -d <directory>     Set target directory"
	print "  -s <line>          Use a specific repository for pulling the dependencies."
	print "                     The parameter will be appended to sources.list."
	print "  -q                 Quiet mode"
	sys.exit(1)

# Create target directory
if "-d" in opts:
	target = opts["-d"]
	if not os.path.isdir(target):
		if target[0] == "/":
			os.chdir("/")
		for part in target.split("/"):
			if part == "":
				continue
			if not os.path.isdir(part):
				os.mkdir(part)
			os.chdir(part)
	else:
		os.chdir(target)
else:
	candidates = map(lambda d: d[:-4], filter(lambda d: d[-4:] == "/bin" and os.path.isdir(d) and os.access(d, os.W_OK), os.environ["PATH"].split(":")))
	if len(candidates) == 0:
		if "-q" not in opts:
			print "Warning: Failed to find writeable prefix directory in $PATH. Defaulting to ~/.local"
			print "Waiting 5 seconds to give you the chance to SIGINT now.."
			time.sleep(5)
		target = os.path.expanduser("~/.local")
	else:
		target = candidates[0]
	os.chdir(target)

# Check for already satisfied dependencies
satisfied = []
if os.access(".packages", os.R_OK):
	satisfied = [ x.trim() for x in open(".packages").readlines() ]

# Create a local copy of the apt-get file structure for
# appending to the sources.list file
aptOptions = ""
if "-s" in opts:
	if not os.path.isdir("_aptlocal"):
		os.mkdir("_aptlocal")
		os.mkdir("_aptlocal/etc")
		os.system("mkdir -p _aptlocal/var/cache/apt/archives/")
		os.system("mkdir -p _aptlocal/var/lib/apt/archives/partial")
		os.system("mkdir -p _aptlocal/var/lib/apt/lists/partial")
		os.system("cp -r /etc/apt/ _aptlocal/etc/")
		repositories = map(lambda x: x[1], filter(lambda x: x[0] == "-s", lopts))
		sourcesList = open("_aptlocal/etc/apt/sources.list", "a")
		for repo in repositories:
			sourcesList.write(repo + "\n")
		sourcesList.close()
	aptOptions = "--force-yes -o Acquire::http::Proxy=0 -o Debug::NoLocking=true --allow-unauthenticated -o Dir=_aptlocal " + ("-qq" if "-q" in opts else "")
	os.system("apt-get " + aptOptions + " update")

packages = args

# Get a list of required packages
packages = os.popen("apt-get install --no-install-recommends --reinstall --print-uris -qq " + aptOptions + " ".join(packages)).readlines()
if "-q" not in opts:
	print len(packages), "packages to go!"

if len(packages) > 5 and "-q" not in opts:
	print "I am going to install:"
	print " - " + "\n - ".join(( os.path.basename(x.split("'")[1]) for x in packages ))
	print "Press <ENTER> to continue"
	raw_input()

# Unpack them
for package in packages:
	uri = package.split("'")[1]
	output = os.path.basename(uri)
	if output in satisfied:
		continue
	os.system("wget %s -O %r %r" % ("-q" if "-q" in opts else "", output, uri))
	dataFile = filter(lambda x: x[:4] == "data", os.popen("ar t %r" % output).readlines())
	if not dataFile:
		print "ERROR: Failed to find datafile in %r" % output
		sys.exit(1)
	dataFile = dataFile[0].strip()
	if os.system("ar x %r %r" % (output, dataFile)) != 0:
		print "ERROR: Failed to extract %s from %s" % (dataFile, output)
		sys.exit(1)
	os.unlink(output)
	if os.system("tar --extract %s --auto-compress --file %r" % ("--verbose" if "-q" not in opts else "", dataFile)) != 0:
		print "ERROR: Failed to unpack %s (from %s)" % (dataFile, output)
		sys.exit(1)
	os.unlink(dataFile)
	satisfied += [ output ]
	open(".packages", "w").write("\n".join(satisfied))
