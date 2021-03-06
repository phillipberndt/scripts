#!/usr/bin/python3
# vim:fileencoding=iso-8859-1:ft=python
#
"""
	runGraphical
	Run a programm in X11 using a shortcut

	Configuration file syntax:

	command {
		.. shell script to execute ..
	}

	or

	command shell line to execute

	lines beginning with # are ignored.
"""
import gi


gi.require_version('Gtk', '3.0')


from gi.repository import Gtk as gtk
from gi.repository import Gdk as gdk
import os
import sys
import re

# Read configuration
try:
	n = -1
	config = open(os.path.expanduser("~/.runGraphical.config")).read()
	config = re.sub("\r\n?", "\n", config)
	commands = {}
	cmdLevel = 0
	while n < len(config) - 1:
		n += 1
		if config[n].isspace():
			continue
		if config[n] == "#":
			n = config.find("\n", n) 
			continue

		command = ""
		while not (config[n].isspace() or n >= len(config)):
			command += config[n]
			n += 1
		while config[n].isspace() and n < len(config) and config[n] != "\n":
			n += 1
		if config[n] == "\n":
			raise Exception("Configuration error")
		execute = ""
		if config[n] != "{":
			while config[n] != "\n" and n < len(config):
				execute += config[n]
				n += 1
		else:
			n += 2
			cmdLevel = 1
			while n < len(config):
				if config[n] == "}":
					cmdLevel -= 1
					if cmdLevel == 0:
						break
				elif config[n] == "{":
					cmdLevel += 1
				execute += config[n]
				n += 1
			if cmdLevel > 0:
				raise Exception("Configuration error")
		commands[command] = execute.strip()
except:
	print("Configuration error in ~/.runGraphical.config in character %d" % n)
	sys.exit(0)

# Show dialog
entry = gtk.Entry()
def check(*x):
	if entry.get_text() in commands:
		gtk.main_quit()
entry.connect("key_release_event", check)
list = gtk.ListStore(str)
for cmd in commands:
	list.set(list.append(), 0, cmd)
completion = gtk.EntryCompletion()
completion.set_model(list)
completion.set_text_column(0)
entry.set_completion(completion)

window = gtk.Window()
window.set_type_hint(gdk.WindowTypeHint.DIALOG)
window.add(entry)
window.connect("hide", lambda *x: gtk.main_quit())
window.set_decorated(gdk.WMDecoration.ALL & (not gdk.WMDecoration.TITLE))
window.set_skip_taskbar_hint(True)
window.set_skip_pager_hint(True)
window.set_keep_above(True)
window.set_modal(True)
window.stick()
window.show_all()
window.move(0, 0)

root = gdk.get_default_root_window()
gdk.keyboard_grab(root, True, gtk.get_current_event_time())
gdk.pointer_grab(root, True, 0, None, None, gtk.get_current_event_time())
entry.grab_focus()

gtk.main()
command = entry.get_text()
gdk.keyboard_ungrab(True)
gdk.pointer_ungrab(True)

del window
del entry
del gtk

# Execute
if command in commands:
	for cmd in commands[command].split("\n"):
		os.system(cmd + " &")

