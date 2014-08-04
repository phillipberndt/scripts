#!/usr/bin/env python
# encoding: utf-8
"""
	venv
	A tool to setup virtual environments for more than just python

	Copyright (c) 2011, Phillip Berndt
	Feel free to reuse and redistribute this program under the terms of the GNU
	Public Licence, which you can find here: http://www.gnu.org/copyleft/gpl.html

	I found that I often need this and that it is complicated to get all the
	neccessary tools, so I decided to write this script.

"""
import exceptions
import optparse
import os
import pwd
import random
import re
import shelve
import signal
import sys
import termios
import time
import tty
import urllib
from abc import *

LIB_DIR_64BIT = "x86_64-linux-gnu"
LIB_DIR_32BIT = "i386-linux-gnu"

def parse_options(): #{{{
	"""
		Parse command line options
	"""
	parser = optparse.OptionParser(usage="usage: %prog [options] <action> [directory]\n\n"
		"The action must be one of:\n"
		" init     Create a new virtual environment\n"
		" enter    Enter a previously created virtual environment\n"
		" setup    Check for required tools and install them if they are absent"
	)
	parser.add_option("-f", "--file", dest="filename",
	  help="write report to FILE", metavar="FILE")
	retval = parser.parse_args()
	if len(retval[1]) == 0 or retval[1][0] not in ("init", "enter", "setup"):
		parser.error("You must specify an action")
	return retval
#}}}
def status(text, mode="info"):#{{{
	"""
		Output a status message

		The mode parameter can take three values which change the output
		preceeding the status message:
		 * info: Outputs a green star before the text
		 * warn: Outputs a yellow star before the text
		 * err:  Outputs two red exclaimation marks before the text
	"""
	codes = { "info": "\033[1;32m * ", "error": "\033[1;31m!! ", "err": "\033[1;31m!! ",
		"warn": "\033[1;33m * ", "warning": "\033[1;33m * ", "normal": "\033[0m" }
	print codes[mode] + codes["normal"] + text
#}}}
def ask(question, use_raw_input = False):#{{{
	"""
		Ask the user for something.

		If you omit the second argument, the question is a yes/no question
		and True/False is returned. Elsewise, the raw input is returned.
	"""
	if use_raw_input:
		return raw_input("\033[1;33m ? \033[0m" + question + ": ")
	print "\033[1;33m ? \033[0m" + question + " [yn]: ",
	sys.stdout.flush()
	fd = sys.stdin.fileno()
	old = termios.tcgetattr(fd)
	try:
		tty.setraw(fd)
		sys.stdin.flush()
		while True:
			character = sys.stdin.read(1)
			if character in ("y", "n"):
				break
	finally:
		termios.tcsetattr(fd, termios.TCSADRAIN, old)
	print character
	return character == "y"
	#}}}
def check_binary(command):#{{{
	"""
		Check if a command is found on the system.

		For example,

		>>> import venv
		>>> venv.check_binary("ls")
		True
		>>> venv.check_binary("woefiwefiwei")
		False

	"""
	return os.system("which \"%s\" 2>&1 > /dev/null" % command.replace('"', r'\"')) == 0
#}}}
def check_prerequisites():#{{{
	"""
		Iterate through the subclasses of VirtualEnvironmentProvider and
		run each's check_prerequisites() method.

		Used to install unavailable tools.
	"""
	if not check_binary("which"):
		status("Failed to locate `which' binary, which is required to check for requisites.", "err")
		sys.exit(1)
	retval = True
	for cls in VirtualEnvironmentProvider.__subclasses__():
		retval &= cls.check_prerequisites()

	return retval
#}}}
def get_temporary_path():#{{{
	"""
		Create a temporary directory in /tmp/ and return it's name
	"""
	while True:
		directory_name = "/tmp/venv-" + str(random.random())
		if os.path.exists(directory_name):
			continue
		os.mkdir(directory_name)
		break
	return directory_name
#}}}
def get_installation_path():#{{{
	"""
		Ask the user for a directory where to install a certain application.

		The question is only asked once per session and then cached. A somewhat
		intelligent guess is made and provided as the default path.
	"""	
	global get_installation_path__saved_setting
	try:
		return get_installation_path__saved_setting
	except NameError:
		pass
	if os.getuid() == 0:
		suggestion = "/usr/local/"
	else:
		suggestion = os.path.expanduser("~/.local/")
		for directory in os.environ["PATH"].split(":"):
			if os.access(directory, os.W_OK):
				suggestion = os.path.abspath(os.path.join(directory, "../"))
				break
	status("Hint: I will always search ~/.venv/ for the tools I need.")
	path = ask("Please specify an installation path [%s]" % suggestion, True)
	if not path:
		path = suggestion
	else:
		path = os.path.expanduser(path)
	if os.path.realpath(os.path.join(path, "bin")) not in os.environ["PATH"]:
		status("This directory is not in your $PATH. Consider putting it into your shell's rc file:", "warn")
		status("PATH=$PATH:%s/bin\n" % path, "warn")
	if not os.path.exists(path):
		os.mkdir(path)
		for suffix in ("bin", "lib"):
			os.mkdir(os.path.join(path, suffix))
	get_installation_path__saved_setting = path
	return path
#}}}
def initialize_virtual_environment(directory, preset=""): #{{{
	"""
		Initialize a virtual environment in a given directory.

		The preset parameter is optional: If you supply it and it matches one
		of the presets defined in the global variable named_configs, the
		classes mentioned there will be used. If you omit it, the user will be
		asked for the classes to use.
	"""
	os.chdir(directory)
	if os.path.isdir(".venv"):
		status(".venv does already exist. Delete the directory first if you really want to reinitialize", "err")
		if ask("Do you want me do delete the .venv directory?"):
			status("Deleting .venv", "warn")
			os.system("rm -rf .venv/")
		else:
			sys.exit(1)
	os.mkdir(".venv")
	config_shelve = shelve.open(".venv/config", writeback=True)
	config_shelve["classes"] = []
	if preset in named_configs:
		status("Using preset " + preset)
		for cls in named_configs[preset]:
			config_shelve["classes"] += [ repr(cls) ]
			if not cls.initialize(config_shelve):
				status("Initialization failed!", "err")
				sys.exit(1)
	else:
		for cls in VirtualEnvironmentProvider.__subclasses__():
			if cls.is_mandatory() or ask("Do you want support for %s" % cls.human_readable_name()):
				config_shelve["classes"] += [ repr(cls) ]
				if not cls.initialize(config_shelve):
					status("Initialization failed!", "err")
					sys.exit(1)
		status("Hint: You can also supply a configuration preset after the `init' command to automate the above selection!")
		status(" available presets are " + ", ".join(named_configs.keys()[:-1]) + " and " + named_configs.keys()[-1])
		status("Initialization successful.")
	config_shelve.close()
#}}}
def enter_virtual_environment(directory):#{{{
	"""
		Enter a virtual environment.
		
		Reads the classes to be used from the .venv subdirectory of directory
		and invokes the enter() methods of each of them.
	"""
	os.chdir(directory)
	status("Entering virtual environment")
	config_shelve = shelve.open(".venv/config", writeback=True)
	for cls in VirtualEnvironmentProvider.__subclasses__():
		if repr(cls) not in config_shelve["classes"]:
			continue
		if not cls.enter(config_shelve):
			status("Initialization failed!", "err")
			sys.exit(1)
	set_ld_preload()
	shell = pwd.getpwuid(os.getuid()).pw_shell
	os.execl(shell, shell)
	#}}}
add_ld_preload__preloaded = ""
def add_ld_preload(library):#{{{
	"""
		Add a library to be put into LD_PRELOAD before finally entering the
		environment.

		This is better than adding it directly in enter() because other
		class'es enter() methods could spawn other processed which would then
		include the LD_PRELOAD-variable

		This function has built-in multi-arch support: If you supply
		 /foo/bar/libbaz.so
		and
		 /foo/bar/x86_64-linux-gnu/libbaz.so
		exists, it adds $LIB as an intermediate path (see ld.so(8) manpage)
	"""

	global add_ld_preload__preloaded
	l_dir, l_file = os.path.split(library)
	if os.access(l_dir + "/" + LIB_DIR_64BIT + "/" + l_file, os.F_OK):
		library = "/".join(l_dir.split("/")[:-1]) + "/${LIB}/" + l_file
	add_ld_preload__preloaded += library + ":"
#}}}
def set_ld_preload():#{{{
	"""
		Set the LD_PRELOAD environment variable to the value(s) from the
		previously called add_ld_preload calls.

		So

		>>> import venv, os
		>>> venv.add_ld_preload("/lib/libc.so")
		>>> venv.add_ld_preload("test.so")
		>>> venv.set_ld_preload()
		>>> os.environ["LD_PRELOAD"] == "/lib/libc.so:test.so"
		True

	"""
	
	global add_ld_preload__preloaded
	os.environ["LD_PRELOAD"] = add_ld_preload__preloaded[:-1]
#}}}
def find_library(relative_to_executable, library):#{{{
	"""
		Find a library.

		This function searches different places for the library:
		 * First, the directories from LD_LIBRARY_PATH are searched
		 * Then, /usr/lib, /lib, ~/.local/lib and ~/.venv/lib are searched
		 * Finally the function searches the $PATH for the executable from
		   relative_to_executable. If it is found, the library is searched
		   for in $PATH/../lib/

		The complete path of the found library is returned, or False.
	"""
	
	# First, try to find the library in typical spots
	lib_paths = os.environ["LD_LIBRARY_PATH"].split(":") if "LD_LIBRARY_PATH" in os.environ else []
	lib_paths += [ "/usr/lib", "/lib", os.path.expanduser("~/.local/lib"), os.path.expanduser("~/.venv/lib") ]
	for path in lib_paths:
		path = os.path.join(path, library)
		if os.access(path, os.R_OK):
			return path
	# Then, try it relative to the given executable
	executable = os.popen("which '%s'" % (relative_to_executable.replace("'", r"\'")), "r").read().strip()
	if not os.access(executable, os.R_OK):
		return False
	library = os.path.abspath(os.path.join(os.path.dirname(executable), library))
	if not os.access(library, os.R_OK):
		return False
	return library
#}}}

class VirtualEnvironmentProvider(object):#{{{
	"""
		This class is the base class for all possible virtual environments.
	"""
	__metaclass__ = ABCMeta
	@staticmethod
	def is_mandatory():
		"""
			If this function returns True, the user is never asked if the class
			should be used.
		"""
		return False
	@staticmethod
	@abstractmethod
	def human_readable_name():
		"""
			Return a human readable name for the provider
		"""
		return "<virtual>"
	@staticmethod
	def check_prerequisites():
		"""
			Check if the required tools are installed and offer the user to
			install them if not.

			This function should also do the actual installation, see
			the helper functions
			 * get_temporary_path
			 * get_installation_path
			 * ask
		"""
		return True
	@staticmethod
	def initialize(config):
		"""
			Initialize an virtual environment in the current directory.

			config is a hash-map which is persistent throughout the lifetime of
			the virtual environment.
		"""
		return True
	@staticmethod
	@abstractmethod
	def enter(config):
		"""
			Enter an virtual environment in the current directory.

			This function should set up the environment and, if required,
			execute daemons etc.
		"""
		
		pass
#}}}
class SandboxProvider(VirtualEnvironmentProvider):#{{{
	"""
		Gentoo sandbox
	"""
	@staticmethod
	def human_readable_name():
		return "sandbox"

	@staticmethod
	def check_prerequisites():
		if not check_binary("sandbox"):
			status("I could not find `sandbox', a tool from Gentoo linux alike Free-BSD's jail.", "warn")
			status("It denies processes write access outside a given directory. While it", "warn")
			status("is not very secure it protects you against unintended write access", "warn")
			status("outside of your virtual environment", "warn")
			if ask("Sandbox is not installed. Install it now?"):
				SandboxProvider.install()
				return True
			return False
		else:
			status("sandbox is already installed")
			return False

	@staticmethod
	def install():
		download_path = get_temporary_path()
		install_path = get_installation_path()
		status("Searching for latest sandbox release")
		distfiles_site = urllib.urlopen("http://mir0.gentoo-fr.org/distfiles/").read()
		candidates = sorted(re.findall('"(sandbox-[^"]+)', distfiles_site))
		distfile = "http://mir0.gentoo-fr.org/distfiles/" + candidates[0]
		basename = os.path.basename(distfile)
		install_sh = os.path.join(download_path, "install.sh")
		with open(install_sh, "w") as file:
			print >> file, "\n".join((
				"cd '%s' || exit 1" % (download_path.replace("'", r"\'")),
				"wget '%s' || exit 1" % (distfile.replace("'", r"\'")),
				"tar axf '%s' || exit 1" % (basename.replace("'", r"\'")),
				"cd */ || exit 1",
				"./configure --prefix='%s' || exit 1" % (install_path.replace("'", r"\'")),
				"make || exit 1",
				"make install || exit 1",
				"mkdir '%s/lib/%s'" % (install_path.replace("'", r"\'"), LIB_DIR_64BIT),
				"mkdir '%s/lib/%s'" % (install_path.replace("'", r"\'"), LIB_DIR_32BIT),
				"ln -s '../libsandbox.so' '%s/lib/%s/'" % (install_path.replace("'", r"\'"), LIB_DIR_64BIT),
				"make clean || exit 1",
				"export CFLAGS='-m32'",
				"./configure --prefix='%s' || exit 1" % (install_path.replace("'", r"\'")),
				"make || exit 1",
				"mv ./libsandbox/.libs/libsandbox.so '%s/lib/%s/libsandbox.so' || exit 1" % (install_path.replace("'", r"\'"), LIB_DIR_32BIT),
				"exit 0"
			))
		status("Installing sandbox")
		if os.system("bash '%s'" % (install_sh)) != 0:
			status("Failed to install sandbox", "err")
		else:
			status("Installed sandbox")

		status("Installing libpwrapper")
		with open(install_sh, "w") as file:
			print >> file, "cd '%s' || exit 1" % (download_path.replace("'", r"\'"))
			for sfile in ("libpwwrapper.c", "Makefile"):
				print >> file, "wget 'https://raw.github.com/phillipberndt/scripts/master/venv/libpwwrapper/%s' || exit 1" % (sfile.replace("'", r"\'"))
			print >> file, "\n".join((
				"make || exit 1",
				"mv libpwwrapper.so '%s/lib/libpwwrapper.so' || exit 1" % (install_path.replace("'", r"\'")),
				"ln -s '../libpwrapper.so' '%s/lib/%s/'" % (install_path.replace("'", r"\'"), LIB_DIR_64BIT),
				"mv libpwwrapper32.so '%s/lib/%s/libpwwrapper.so' || exit 1" % (install_path.replace("'", r"\'"), LIB_DIR_32BIT),
				"exit 0",
			))
		if os.system("bash '%s'" % (install_sh)) != 0:
			status("Failed to install libpwwrapper", "err")
		else:
			status("Installed libpwrapper")

		os.system("rm -rf '%s'" % (download_path.replace("'", r"\'")))

	@staticmethod
	def initialize(config):
		config["has_sandbox"] = True
		return True

	@staticmethod
	def enter(config):
		library = find_library("sandbox", "../lib/libsandbox.so")
		if not library:
			return False
		add_ld_preload(library)
		library = find_library("sandbox", "../lib/libpwwrapper.so")
		if library:
			# sic. This is optional, not everybody might have this.
			add_ld_preload(library)
		os.environ["SANDBOX_ACTIVE"] = "armedandready"
		os.environ["SANDBOX_ON"] = "1"
		os.environ["SANDBOX_PID"] = str(os.getpid())
		os.environ["SANDBOX_READ"] = "/"
		os.environ["SANDBOX_VERBOSE"] = "1"
		os.environ["SANDBOX_WRITE"] = "/dev/fd:/proc/self/fd:/dev/zero:/dev/null:/dev/full:/dev/console:/dev/tty:/dev/vc/:/dev/pty:/dev/tts:/dev/pts/:/dev/shm:/tmp/:/var/tmp/:" + os.getcwd()
		return True
#}}}
class VirtualenvProvider(VirtualEnvironmentProvider):#{{{
	"""
		Python virtualenv
	"""
	@staticmethod
	def human_readable_name():
		return "virtualenv"

	@staticmethod
	def check_prerequisites():
		if not check_binary("virtualenv"):
			status("I could not find `virtualenv'. Virtualenv is a python script to setup", "warn")
			status("locally isolated python installations.", "warn")
			if ask("virtualenv is not installed. Install it now?"):
				VirtualenvProvider.install()
				return True
			return False
		else:
			status("virtualenv is already installed")
			return True

	@staticmethod
	def install():
		install_path = get_installation_path()
		file_name = os.path.join(install_path, "bin/virtualenv")
		urllib.urlretrieve("https://raw.github.com/pypa/virtualenv/master/virtualenv.py", file_name)
		os.chmod(file_name, 0755)
	
	@staticmethod
	def initialize(config):
		status("Initializing virtual environment")
		if os.system("virtualenv ./.venv/") != 0:
			return False
		return True
	
	@staticmethod
	def enter(config):
		directory = os.path.join(os.getcwd(), ".venv/bin")
		if directory not in os.environ["PATH"]:
			os.environ["PATH"] = directory + ":" + os.environ["PATH"]
		return True

#}}}
class WinePrefixProvider(VirtualEnvironmentProvider):#{{{
	"""
		Put a WINEPREFIX inside the virtual environment
	"""
	@staticmethod
	def human_readable_name():
		return "wine"
	@staticmethod
	def initialize(config):
		os.mkdir(".venv/wine")
		return True
	@staticmethod
	def enter(config):
		os.environ["WINEPREFIX"] = os.path.join(os.getcwd(), ".venv/wine")
		return True
#}}}
class EnvironmentProvider(VirtualEnvironmentProvider):#{{{
	"""
		Setup the environment such that there is an isolated $HOME in the
		virtual environment and set $PATH accordingly.
	"""
	@staticmethod
	def is_mandatory():
		return True
	@staticmethod
	def human_readable_name():
		return "isolated $home"
	@staticmethod
	def enter(config):
		for base in (".venv", ".local"):
			directory = os.path.join(os.getcwd(), ".venv")
			if directory not in os.environ["PATH"]:
				os.environ["PATH"] = os.path.join(directory, "bin") + ":" + os.environ["PATH"]
			if directory not in os.environ["LD_LIBRARY_PATH"]:
				os.environ["LD_LIBRARY_PATH"] = os.path.join(directory, "lib") + ":" + os.environ["LD_LIBRARY_PATH"]
		os.environ["HOME"] = os.getcwd()
		return True
	@staticmethod
	def initialize(config):
		open(".zshrc", "w").write('export PS1="[sandbox] $PS1"')
		open(".bashrc", "w").write('export PS1="[sandbox] $PS1"')
		return True
#}}}
class FakeRootProvider(VirtualEnvironmentProvider):#{{{
	"""
		Debian fake root environment.
	"""
	@staticmethod
	def human_readable_name():
		return "fakeroot"
	@staticmethod
	def check_prerequisites():
		if not check_binary("fakeroot"):
			status("I could not find `fakeroot', a debian utility which gives you the", "warn")
			status("ability to fake root-ownership of files.", "warn")
			if ask("fakeroot not found. Install it now?"):
				FakeRootProvider.install()
				return True
		else:
			status("fakeroot is installed")
			return True
		return False
	@staticmethod
	def install():
		download_path = get_temporary_path()
		install_path = get_installation_path()
		status("Searching for latest fakeroot release")
		fakeroot_dist = urllib.urlopen("http://ftp.debian.org/debian/pool/main/f/fakeroot/").read()
		files = sorted(re.findall('"(fakeroot_[^"]+\.orig\.[^"]+)', fakeroot_dist))
		download_file = "http://ftp.debian.org/debian/pool/main/f/fakeroot/" + files[0]
		install_sh = os.path.join(download_path, "install.sh")
		with open(install_sh, "w") as file:
			print >> file, "cd '%s' || exit 1" % (download_path.replace("'", r"\'"))
			print >> file, "wget '%s' || exit 1" % (download_file.replace("'", r"\'"))
			print >> file, "tar axf fakero* || exit 1"
			print >> file, "cd */ || exit 1"
			print >> file, "./configure --prefix='%s' || exit 1" % (install_path.replace("'", r"\'"))
			print >> file, "make || exit 1"
			print >> file, "make install || exit 1"
		status("Installing fakeroot")
		if os.system("bash '%s'" % (install_sh)) != 0:
			status("Failed to install fakeroot", "err")
		else:
			status("Installed fakeroot")
		os.system("rm -rf '%s'" % (download_path.replace("'", r"\'")))
	@staticmethod
	def initialize(config):
		if "has_sandbox" in config:
			status("Warning: Activating fakeroot and sandbox simultaneously can - and in fact will - cause trouble!", "warn")
		os.system("touch .venv/fakerootstate")
		return True
	@staticmethod
	def enter(config):
		fakeroot_state_file = os.path.abspath(".venv/fakerootstate")
		(fakeroot_key, pid) = os.popen("faked-tcp --save-file %s --load < %s"
			% (fakeroot_state_file, fakeroot_state_file), "r").read().split(":")
		os.environ["FAKED_MODE"] = "unknown-is-root"
		os.environ["FAKEROOTKEY"] = fakeroot_key
		library = find_library("fakeroot", "../lib/libfakeroot/libfakeroot-tcp.so")
		if not library:
			library = find_library("fakeroot", "../lib/libfakeroot-tcp.so")
		if not library:
			library = find_library("fakeroot", "../lib/libfakeroot.so")
		if not library:
			os.kill(int(pid), signal.SIGTERM)
			return False
		child_pid = os.fork()
		if child_pid != 0:
			os.wait()
			os.kill(int(pid), signal.SIGTERM)
			sys.exit(0)
		add_ld_preload(library)
		return True
#}}}

named_configs = {#{{{
	"wine": [
		SandboxProvider,
		WinePrefixProvider,
		EnvironmentProvider
	],
	"python": [
		VirtualenvProvider,
		EnvironmentProvider
	],
	"fakeroot": [
		EnvironmentProvider,
		FakeRootProvider
	]
}#}}}

def main():
	(options, args) = parse_options()
	if len(args) == 1:
		args += [ "." ]
	if not os.path.isdir(args[1]):
		status("Creating directory " + args[1])
		os.mkdir(args[1])
	args[1] = os.path.abspath(args[1])

	if args[0] == "setup":
		check_prerequisites()
	elif args[0] == "init":
		if len(args) == 2:
			args += [ "" ]
		initialize_virtual_environment(args[1], args[2])
		if ask("Do you want to enter the environment?"):
			enter_virtual_environment(args[1])
	elif args[0] == "enter":
		if not os.path.isdir(os.path.join(args[1], ".venv")):
			status("This virtual environment does not exist yet. I will now initialize it..", "warn")
			initialize_virtual_environment(args[1], "")
		enter_virtual_environment(args[1])

if __name__ == '__main__':
	main()
