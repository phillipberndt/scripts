#!/usr/bin/env python
# encoding: utf-8
"""
    A simple livereload implementation using tornado and pyinotify

    Run this in the document root of the web/development server and
    put

     <script src="http://localhost:35729/livereload.js"></script>

    in your document.
"""

import tornado.web, tornado.ioloop, tornado.websocket
import json
import pyinotify
import os

active_sockets = []

class LiveReloadSocket(tornado.websocket.WebSocketHandler):
    def open(self):
        self.hello_received = False
        self.write_message(json.dumps(
            { "command": "hello",
              "protocols": [ "http://livereload.com/protocols/official-7" ]
            }))
        active_sockets.append(self)

    def send_update(self, file):
        if not self.hello_received:
            return

        self.write_message(json.dumps(
            { "command": "reload",
              "path": file,
              "liveCSS": True
            }))

    def on_message(self, message):
        self.hello_received = True

    def on_close(self):
       self.hello_received = False
       active_sockets.remove(self)

def inotify_handler(event):
    if (event.mask & pyinotify.IN_CLOSE_WRITE) and not (event.mask & pyinotify.IN_ISDIR):
        file_name = os.path.join(event.path, event.name)
        if os.path.isfile(file_name):
            if file_name[0] == ".":
                file_name = file_name[1:]
            for socket in active_sockets:
                socket.send_update(file_name)

if __name__ == "__main__":
    application = tornado.web.Application([
        (r"/(livereload.js)", tornado.web.StaticFileHandler, {'path': "js"}),
        (r"/livereload", LiveReloadSocket),
    ])
    application.listen(35729)
    ioloop = tornado.ioloop.IOLoop.instance()

    wm = pyinotify.WatchManager()
    inotifier = pyinotify.Notifier(wm, inotify_handler)
    wm.add_watch(".", pyinotify.ALL_EVENTS, rec=True)
    def inotify_fd_handler(*args):
        inotifier.process_events()
        if inotifier.check_events():
            inotifier.read_events()
            inotifier.process_events()

    ioloop.add_handler(wm.get_fd(), inotify_fd_handler, ioloop.READ)

    ioloop.start()
