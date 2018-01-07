#!/usr/bin/python
# vim:fileencoding=utf-8:ft=python
#
"""
	Paste a password from a GPG encrypted password file to open
	applications.
	Copyright (c) 2007-2011, Phillip Berndt

	You should bind this script to a hotkey in your WM.
	The password file must be located in ~/.myshadow, encrypted with GnuPG.
"""
import sys
import re
import os
import time
try:
	import Xlib.display, Xlib.XK
	from Xlib.keysymdef import latin1

except:
	print >> sys.stderr, (
		"This script needs the python Xlib bindings\n"
		"Download them at http://python-xlib.sourceforge.net"
		)
	sys.exit(1)
try:
	import gtk
except:
	print >> sys.stderr, (
		"This script needs pyGTK\n",
		"Download it at http://www.pygtk.org"
		)
	sys.exit(1)

def handle_pending_events(): #{{{
	"""
		Handle all pending GTK events
	"""
	while gtk.events_pending():
		gtk.main_iteration_do()
#}}}
def error_message(msg): #{{{
	"""
		Show an error message dialog
	"""
	dialog = gtk.MessageDialog(None, gtk.DIALOG_MODAL, gtk.MESSAGE_ERROR, gtk.BUTTONS_OK, msg)
	dialog.set_title("passwrd: Failure")
	dialog.run()
	dialog.hide()
	handle_pending_events()
	dialog.destroy()
	handle_pending_events()
#}}}
def ask(title, question, pre_fill = False):#{{{
	"""
		Ask for something and return it
	"""
	done_ok = [ False ]
	def hide(x):
		done_ok[0] = True
		my_window.hide()
		gtk.main_quit()
	my_window = gtk.Window()
	my_window.connect("hide", hide)
	my_window.set_title("passwrd: " + title)
	my_window.set_default_size(300, 120)
	my_window.set_border_width(10)
	my_window.set_position(gtk.WIN_POS_MOUSE)
	my_vbox = gtk.VBox()
	my_window.add(my_vbox)
	my_hbox = gtk.HBox()
	my_vbox.add(my_hbox)
	my_image = gtk.image_new_from_icon_name("gtk-dialog-question", 3)
	my_hbox.add(my_image)
	my_label = gtk.Label(question)
	my_label.set_padding(3, 3)
	my_hbox.add(my_label)
	my_entry  = gtk.Entry()
	if pre_fill:
		my_entry.set_text(pre_fill)
	my_entry.set_activates_default(True)
	my_vbox.add(my_entry)
	my_button = gtk.Button()
	my_button.set_label("Ok")
	my_button.connect("clicked", hide)
	my_button.set_flags(gtk.CAN_DEFAULT)
	my_button.set_image(gtk.image_new_from_icon_name("gtk-ok", -1))
	my_window.set_default(my_button)
	my_hbox2 = gtk.HBox()
	my_hbox2.add(gtk.Label())
	my_hbox2.add_with_properties(my_button, "expand", False, "fill", False)
	my_hbox2.add(gtk.Label())
	my_vbox.add(my_hbox2)
	my_window.show_all()
	gtk.main()
	search = my_entry.get_text()
	my_window.destroy()
	handle_pending_events()
	if not done_ok[0]:
		sys.exit(1)
	return search
#}}}
def window_name(window):#{{{
	"""
		Get the window-wm-title of the parent window of a widget having
		the focus. window must be an X11 window
	"""
	wm_name = window.get_wm_name()
	while not wm_name:
		query = window.query_tree()
		if query.parent == query.root:
			return "-unknown-"
		window = query.parent
		try:
			wm_name = window.get_wm_name()
		except:
			pass
	return wm_name
#}}}
def send_string(window, text):#{{{
	"""
		Send a string to a window
	"""
	display = Xlib.display.Display()
	Xlib.XK.load_keysym_group("xkb")
	keysym_map = dict((Xlib.XK.keysym_to_string(x), x) for x in latin1.__dict__.values() if type(x) is int )
	for char_index in range(len(text)):
		char = text[char_index]
		if char in keysym_map:
			key_sym = keysym_map[char]
		else:
			if char == "\t": char = "Tab"
			elif char == "\n": char = "Return"
			key_sym = Xlib.XK.string_to_keysym(char)
			if not key_sym:
				continue
		key_codes = display.keysym_to_keycodes(key_sym)
		if not key_codes:
			continue
		key_code, index = key_codes[0]

		m_state = 0
		if index & 1:
			# Shift
			m_state = 1
		if index & 4 | index & 2:
			# Alt Grid
			m_state = m_state | 0x80
		for m_type in (Xlib.protocol.event.KeyPress, Xlib.protocol.event.KeyRelease):
			ev = m_type(time=0, child=0, state=m_state, root=window.query_tree().root, window=window, same_screen=1, \
				root_x=0, root_y=0, event_x=0, event_y=1, detail=key_code)
			window.send_event(ev)
			display.sync()
#}}}

if __name__ == "__main__":
	# Open display
	try:
		display = Xlib.display.Display()
	except:
		print >> sys.stderr, "Failed to open the display"
		sys.exit(1)

	# Get the active window (widget)
	focus_widget = display.get_input_focus().focus

	# Get wm title
	match_title = title = window_name(focus_widget)
	uninteresting_strings = (" - Mozilla Firefox", " - Chromium", " - Opera")
	for string in uninteresting_strings:
		match_title = match_title.replace(string, "")
	
	print "Password match against: ", match_title

	# Load the passfile
	pass_text = ""
	pw_data = os.popen("gpg -d --use-agent --batch -q --no-tty <~/.myshadow").readlines()
	if len(pw_data) == 0:
		error_message("Failed to decrypt the shadow file.")
		sys.exit(1)
	pw_data = [ (guess.group(1), guess.group(2)) for guess in (re.match("^(?!#)([^\t]+)\t\s*(.+)\s*$", line) for line in pw_data) if guess ]

	# Password matching: First try to do some intelligent guessing
	guess = False
	for description, password in pw_data:
		description = re.sub("\s*\(.+\)\s*$", "", description)
		if re.search(description, match_title, re.I):
			guess = description
			break

	# Then ask the user
	search = ask("Enter search string", "Which password do you want?", guess)

	# Check if he requested only a part
	partial = re.search("\(([0-9]+)\)\s*$", search)
	if partial:
		search = search[:-len(partial.group(0))].strip()
		partial = int(partial.group(1))
		print("Partial search: Partial %d, rest %s" % (partial, search))

	# Then do the search
	for description, password in pw_data:
		if re.search(search, description, re.I):
			if search != description:
				question_dialog = gtk.MessageDialog(type=gtk.MESSAGE_QUESTION, buttons=gtk.BUTTONS_YES_NO)
				question_dialog.set_markup("Enter password for " + description + "?")
				response = question_dialog.run()
				question_dialog.destroy()
				handle_pending_events()
				if response != gtk.RESPONSE_YES:
					continue
			pass_text = password.strip()
			break
	del pw_data

	if not pass_text:
		error_message("Failed to find a password.")
	else:
		if partial:
			try:
				pass_text = pass_text.split()[partial-1].strip()
			except:
				error_message("Password has no part %d." % partial)
				sys.exit(1)
		# Send keyboard events
		time.sleep(0.1)
		send_string(focus_widget, pass_text)
