#!/usr/bin/python
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
import gtk
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
	print "Configuration error in ~/.runGraphical.config in character %d" % n
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
window.set_type_hint(gtk.gdk.WINDOW_TYPE_HINT_DIALOG)
window.add(entry)
window.connect("hide", lambda *x: gtk.main_quit())
window.set_decorated(gtk.gdk.DECOR_ALL & (not gtk.gdk.DECOR_TITLE))
window.set_skip_taskbar_hint(True)
window.set_skip_pager_hint(True)
window.set_keep_above(True)
window.set_modal(True)
window.stick()
window.show_all()
window.move(0, 0)

root = gtk.gdk.get_default_root_window()
gtk.gdk.keyboard_grab(root, True, gtk.get_current_event_time())
gtk.gdk.pointer_grab(root, True, 0, None, None, gtk.get_current_event_time())
entry.grab_focus()

gtk.main()
command = entry.get_text()
gtk.gdk.keyboard_ungrab()
gtk.gdk.pointer_ungrab()

del window
del entry
del gtk

# Execute
if command in commands:
	for cmd in commands[command].split("\n"):
		os.system(cmd + " &")

