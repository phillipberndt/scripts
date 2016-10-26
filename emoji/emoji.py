#!/usr/bin/env python
# encoding: utf-8
#
# Simple script to let the user select an emoji and copy it into the clipboard
# Copyright (c) 2016, Phillip Berndt
#
import base64
import os
import re
import requests
import shelve
import time

import gi
gi.require_version("Gtk", "3.0")

from gi.repository import Gtk, GObject, GdkPixbuf, Gdk

import Xlib.display
import ctypes

EMOJI_LIST_URL    = "http://www.unicode.org/emoji/charts/full-emoji-list.html"
EMOJI_LIST_REGEXP = u"(?s)<tr>(?:(?!</tr>|<img).)+<img(?:(?!</tr>|<img).)+<img alt='(?P<codepoint>[^']+)'[^>]+src='(?P<image>data:image/[^']+)'[^>]*>(?:(?!</tr>).)*<td class='name'>(?P<name>[^<]+)"

def get_emoji_cache():
    """
        Returns a dictionary with emoji mnenorics as keys and (codepoint,
        image, mnenoric) dictionaries as entries, where image is a binary data
        stream representing the emoji as a PNG file. Said dictionary is cached
        automatically.
    """
    emoji_cache = shelve.open(os.path.expanduser("~/.cache/emoji.py.db"), protocol=-1, writeback=True)

    if not emoji_cache:
        emoji_list = requests.get(EMOJI_LIST_URL).text
        for match in re.finditer(EMOJI_LIST_REGEXP, emoji_list):
            key = match.group("name").encode("utf8")
            emoji_cache[key] = match.groupdict()
            emoji_cache[key]["image"] = base64.b64decode(emoji_cache[key]["image"][emoji_cache[key]["image"].find("base64,") + 7:])

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
            display.change_keyboard_mapping(254, [ [xlib_unicode_cp_to_keysym(ord(character))] ])

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
        needle = search_bar.get_text().lower()
        if not needle:
            return True
        codepoint = model.get_value(iterator, 1)
        name = model.get_value(iterator, 2).lower()
        return needle in name or needle in codepoint

    def _key_press_func(widget, event):
        "Event handler to exit on enter / double click"
        if (event.get_event_type() == Gdk.EventType.KEY_PRESS and event.get_keycode().keycode in (36, 104)) or \
                event.get_event_type() == getattr(Gdk.EventType, "2BUTTON_PRESS"):
            model, iterator = tree_view.get_selection().get_selected()
            if iterator is None:
                iterator = model.get_iter_first()

            try:
                codepoint = model.get_value(iterator, 1)
            except:
                return False

            #clipboard = Gtk.Clipboard.get(Gdk.SELECTION_CLIPBOARD)
            #clipboard.set_text(codepoint, -1)
            #clipboard.store()

            window.retval = codepoint.decode("utf8")

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

    tree_model = Gtk.ListStore(GdkPixbuf.Pixbuf, GObject.TYPE_STRING, GObject.TYPE_STRING)
    tree_model_filter = tree_model.filter_new()
    tree_model_filter.set_visible_func(_filter_func, search_bar)

    for emoji in sorted(get_emoji_cache().values(), key=lambda x: x["name"]):
        loader = GdkPixbuf.PixbufLoader()
        loader.write(emoji["image"])
        loader.close()
        tree_model.append((loader.get_pixbuf().scale_simple(32, 32, 0), emoji["codepoint"], emoji["name"]))

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
    return window.retval


if __name__ == "__main__":
    focus_widget = xlib_get_active_window()
    emoji = get_emoji()
    xlib_send_string(emoji, focus_widget)
