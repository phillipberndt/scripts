#!/usr/bin/env python
# encoding: utf-8
#
# Simple script to let the user select an emoji or other Unicode symbol and
# copy it into the clipboard
#
# Copyright (c) 2016, Phillip Berndt
#
import base64
import os
import re
import requests
import shelve
import subprocess
import time

import gi
gi.require_version("Gtk", "3.0")

from gi.repository import Gtk, GObject, GdkPixbuf, Gdk

import Xlib.display
import ctypes

# Emoji have nice HTML charts with images. Use those!

EMOJI_LIST_URL    = ( #"http://www.unicode.org/emoji/charts/full-emoji-list.html",
                      "http://www.unicode.org/emoji/charts-beta/full-emoji-list.html",
                    )
EMOJI_LIST_REGEXP = ur"""(?sx)<tr>(?:(?!</tr>|<img).)+                       # At the start of an emoji definition
                        <img(?:(?!</tr>|<img).)+                             # Skip the first image (ugly reference chart picture)
                        # Extract the data from the 2nd (Apple) reference image instead:
                        <img\ alt='(?P<codepoint>[^']+)'[^>]+src='(?P<image>data:image/[^']+)'[^>]*>(?:(?!</tr>).)*
                        <td\ class='name'>(?P<name>[^<]+)(?:(?!</tr>).)*     # Fetch the name of the emoji
                    """

# Other symbols have a PDF. For now, extract using pdftotext and strip the
# images. Maybe I'll extend this to include the images someday.

PDF_SYMBOLS_URL = (
                    "http://unicode.org/charts/PDF/U2190.pdf",
                    "http://unicode.org/charts/PDF/U1D400.pdf",
                    "http://unicode.org/charts/PDF/U2200.pdf",
                    "http://unicode.org/charts/PDF/U25A0.pdf",
                    "http://unicode.org/charts/PDF/U2700.pdf",
                    "http://unicode.org/charts/PDF/U2600.pdf",
                    "http://unicode.org/charts/PDF/U1F300.pdf",
                    "http://unicode.org/charts/PDF/U1F900.pdf",
                    "http://unicode.org/charts/PDF/U1F680.pdf",
                    "http://unicode.org/charts/PDF/U2B00.pdf",
                    "http://unicode.org/charts/PDF/U2100.pdf",
                    "http://unicode.org/charts/PDF/U1D400.pdf",
                    "http://unicode.org/charts/PDF/U1EE00.pdf",
                    "http://unicode.org/charts/PDF/U2460.pdf",
                    "http://unicode.org/charts/PDF/U2300.pdf",
                  )

PDF_SYMBOLS_REGEXP = ur"""(?sm)^[0-9A-F]{2,} (?P<codepoint>.) (?P<explaination>[A-Z ]+)(?:\s+^= (?P<annotations>(?:(?!\n).)+))?"""

def get_emoji_cache():
    """
        Returns a dictionary with emoji mnenorics as keys and (codepoint,
        image, mnenoric) dictionaries as entries, where image is a binary data
        stream representing the emoji as a PNG file. Said dictionary is cached
        automatically.
    """
    emoji_cache_file = os.path.expanduser("~/.cache/emoji.py.db")

    if os.path.isfile(emoji_cache_file) and os.stat(emoji_cache_file).st_mtime < time.time() - 3600*24*365/2:
        # Regenerate the cache.
        os.unlink(emoji_cache_file)

    emoji_cache = shelve.open(emoji_cache_file, protocol=-1, writeback=True)

    if not emoji_cache:
        for url in EMOJI_LIST_URL:
            emoji_list = requests.get(url).text
            for match in re.finditer(EMOJI_LIST_REGEXP, emoji_list):
                key = match.group("codepoint").encode("utf8")
                data = match.groupdict()
                data["annotations"] = []
                data["image"] = base64.b64decode(data["image"][data["image"].find("base64,") + 7:])
                emoji_cache[key] = data

        for url in PDF_SYMBOLS_URL:
            symbols_data = requests.get(url).content
            symbols_text = subprocess.Popen(["pdftotext", "-", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE).communicate(symbols_data)[0].decode("utf8")
            for match in re.finditer(PDF_SYMBOLS_REGEXP, symbols_text):
                key = match.group("codepoint").encode("utf8")
                data = { "name":  match.group("explaination").lower(), "codepoint": match.group("codepoint"),
                         "annotations": [ x.strip() for x in match.group("annotations").split(",") ] if match.group("annotations") else [], "image": None }
                # Symbols from PDFs never overwrite emoji's with images
                if key not in emoji_cache:
                    emoji_cache[key] = data

        emoji_cache.sync()

    return emoji_cache

_lib_cache = [None, None]
def xlib_get_display():
    if _lib_cache[0] is None:
        _lib_cache[0] = Xlib.display.Display()
    return _lib_cache[0]

def xlib_unicode_cp_to_keysym(codepoint):
    "Return keysym for Unicode codepoint. Worst hack ever."
    if _lib_cache[1] is None:
        _lib_cache[1] = ctypes.CDLL("libX11.so")
    return _lib_cache[1].XStringToKeysym("U%08X" % codepoint)

def xlib_get_active_window():
    "Return the Xlib window which has the input focus"
    return xlib_get_display().get_input_focus().focus

def xlib_send_string(text, window=None):
    """
        Send a string to a window by remapping the keyboard. Slow, but works
        with all Unicode characters.
    """
    if type(text) is not unicode:
        text = text.decode("utf8")
    if not window:
        window = xlib_get_active_window()
    display = xlib_get_display()

    original_mapping = display.get_keyboard_mapping(254, 1)

    try:
        for character in text:
            display.change_keyboard_mapping(254, [ [xlib_unicode_cp_to_keysym(ord(character))] * len(original_mapping[0]) ])

            display.sync()
            for m_type in (Xlib.protocol.event.KeyPress, Xlib.protocol.event.KeyRelease):
                    ev = m_type(time=0, child=0, state=0, root=window.query_tree().root, window=window, same_screen=1, \
                            root_x=0, root_y=0, event_x=0, event_y=1, detail=254)
                    window.send_event(ev)
                    display.sync()
            time.sleep(0.05)

            pass
    finally:
        display.change_keyboard_mapping(254, original_mapping)

def create_window():
    """
        Create the main application window and return a handle
    """
    def _filter_func(model, iterator, search_bar):
        "TreeView filter function -- search for emoji"
        needle = search_bar.get_text().lower().split()
        if not needle:
            return True
        codepoint = model.get_value(iterator, 1)
        name = model.get_value(iterator, 2).lower()
        annotations = model.get_value(iterator, 3)

        for element in needle:
            if element not in name and element not in codepoint and element not in annotations:
                return False
        return True

    def _key_press_func(widget, event):
        "Event handler to exit on enter / double click"
        if event.get_event_type() == Gdk.EventType.KEY_PRESS and event.get_keycode().keycode == 9: # ESC
            window.hide()
            GObject.idle_add(Gtk.main_quit, None)

        # (36, 104) == enter keys
        if (event.get_event_type() == Gdk.EventType.KEY_PRESS and event.get_keycode().keycode in (36, 104)) or \
                event.get_event_type() == getattr(Gdk.EventType, "2BUTTON_PRESS"):
            model, iterator = tree_view.get_selection().get_selected()
            if iterator is None:
                iterator = model.get_iter_first()

            try:
                codepoint = model.get_value(iterator, 1)
            except:
                return False

            window.retval = codepoint.decode("utf8")
            window.hide()
            GObject.idle_add(Gtk.main_quit, None)

            return True
        return False


    window = Gtk.Window()
    window.set_title("Emoji selector")
    window.set_size_request(500, 800)

    stacker = Gtk.VBox()
    window.add(stacker)

    search_bar = Gtk.Entry()
    stacker.pack_start(search_bar, False, False, 1)

    tree_model = Gtk.ListStore(GdkPixbuf.Pixbuf, GObject.TYPE_STRING, GObject.TYPE_STRING, GObject.TYPE_STRING)
    for emoji in sorted(get_emoji_cache().values(), key=lambda x: x["name"]):
        if emoji["image"]:
            loader = GdkPixbuf.PixbufLoader()
            loader.write(emoji["image"])
            loader.close()
            pixbuf = loader.get_pixbuf().scale_simple(32, 32, 0)
        else:
            pixbuf = None
        tree_model.append((pixbuf, emoji["codepoint"], emoji["name"], "; ".join(emoji["annotations"]).lower()))

    tree_model_filter = tree_model.filter_new()
    tree_model_filter.set_visible_func(_filter_func, search_bar)
    tree_view = Gtk.TreeView(tree_model_filter)

    pixbuf = Gtk.CellRendererPixbuf()
    pixbuf.props.yalign = 0
    pixbuf.props.ypad = 3
    pixbuf.props.xpad = 3
    cp_renderer = Gtk.CellRendererText()
    cp_renderer.props.font = "Symbola 32"
    tree_view.append_column(Gtk.TreeViewColumn("Icon", pixbuf, pixbuf=0))
    tree_view.append_column(Gtk.TreeViewColumn("Codepoint", cp_renderer, text=1))
    tree_view.append_column(Gtk.TreeViewColumn("Name", Gtk.CellRendererText(), text=2))

    container = Gtk.ScrolledWindow()
    stacker.pack_start(container, True, True, 1)
    container.add(tree_view)

    window.connect("hide", Gtk.main_quit)
    search_bar.connect("changed", lambda *args: tree_model_filter.refilter())
    search_bar.connect("key-press-event", _key_press_func)
    tree_view.connect("key-press-event", _key_press_func)
    tree_view.connect("button-press-event", _key_press_func)

    return window

def get_emoji():
    "Querys the user for an emoji"
    window = create_window()
    window.show_all()
    Gtk.main()
    try:
        return window.retval
    except AttributeError:
        return False

def set_clipboard(text):
    def _setter():
        clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
        clipboard.set_text(text, -1)
        clipboard.store()
        Gtk.main_quit()
    GObject.idle_add(_setter)
    Gtk.main()


if __name__ == "__main__":
    if False:
        time.sleep(0.1)
        focus_widget = xlib_get_active_window()
        emoji = get_emoji()
        if emoji:
            time.sleep(0.1)
            xlib_send_string(emoji, focus_widget)
    else:
        emoji = get_emoji()
        if emoji:
            set_clipboard(emoji)
