#!/usr/bin/env python3
# encoding: utf-8
import fcntl
import io
import os
import re
import signal
import struct
import sys
import termios
import time

from itertools import chain

try:
    from psutil import Process, process_iter
    HAS_PSUTIL = True
except:
    HAS_PSUTIL = False

TEXT_RED = "\033[31m"
TEXT_GREEN = "\033[32m"
TEXT_YELLOW = "\033[33m"
TEXT_BOLD = "\033[1m"
TEXT_HALF_BRIGHT = "\033[2m"
TEXT_DEFAULT = "\033[0m"
TEXT_ERASE = "\033[H\033[J"
TEXT_TO_ALTERNATE = "\033[?1049h"
TEXT_TO_NORMAL = "\033[?1049l"
TEXT_BG_GREY = "\033[47m"


class Highlight(str):
    def __repr__(self):
        return "*%s*" % (str(self),)


if not HAS_PSUTIL:
    def process_iter():
        for pid in os.listdir("/proc/"):
            if pid.isdigit():
                yield Process(int(pid))

    class Process(object):
        def __init__(self, pid=None):
            if not pid:
                pid = os.getpid()
            if sys.version < '3' and isinstance(pid, long):
                pid = int(pid)
            self.pid = pid

        def __enter__(self):
            return self

        def __exit__(self, type, value, tb):
            pass

        def oneshot(self):
            return self

        def cmdline(self):
            cmd_file = os.path.join("/proc/", str(self.pid), "cmdline")
            return io.open(cmd_file).read().split("\0")

        def parent(self):
            try:
                status_file = os.path.join("/proc/", str(self.pid), "status")
                pid = int(re.search("PPid:\s+([0-9]+)", open(status_file).read()).group(1))
                assert pid > 0
            except:
                return None
            return Process(pid)

        def uids(self):
            status_file = os.path.join("/proc/", str(self.pid), "status")
            return list(map(int, [x for x in open(status_file).readlines() if x.startswith("Uid:")][0].split()[1:]))


def ppid_cascade(process=None):
    if process is None:
        process = Process()
    process = process.parent()
    while process:
        yield process.pid
        process = process.parent()

def get_x11_list(for_uid=None):
    try:
        import socket
        import Xlib.display

        dpy = Xlib.display.Display()
    except:
        return

    pid_atom = dpy.get_atom("_NET_WM_PID")
    cl_atom = dpy.get_atom("_NET_CLIENT_LIST")
    wm_name_atom = dpy.get_atom("_NET_WM_NAME")
    hostname = socket.gethostname()

    protected_pids = list(ppid_cascade()) + [ os.getpid() ]

    for wnd_id in dpy.screen().root.get_property(cl_atom, 0, 0, 10000).value:
        wnd = dpy.create_resource_object("window", wnd_id)
        host = wnd.get_wm_client_machine()
        if host != hostname:
            continue
        pid = wnd.get_property(pid_atom, 0, 0, 4)
        if not pid:
            continue
        pid = pid.value[0]
        name = wnd.get_property(wm_name_atom, 0, 0, 10000).value

        if pid in protected_pids:
            continue

        data = query_process(pid)
        if data and (for_uid is None or for_uid == 0 or data["owner"] == for_uid):
            data["cmd_line"] = u"%s [%s]" % (data["cmd_line"], name)
            yield data

def query_process(process=None):
    if not isinstance(process, Process):
        process = Process(process)
    cmd_line = u" ".join((u'"%s"' % x.replace('"', r'\"') if " " in x else x.replace('"', r'\"') \
                         for x in process.cmdline()))
    return {"pid": process.pid, "cmd_line": cmd_line, "owner": process.uids()[0]}

def get_proc_list(for_uid=None):
    protected_pids = list(ppid_cascade()) + [ os.getpid() ]
    for process in process_iter():
        if process.pid in protected_pids:
            continue
        if not for_uid or for_uid in process.uids():
            try:
                yield query_process(process)
            except:
                pass

def get_proc_lists(for_uid=None):
    return chain(get_proc_list(for_uid), get_x11_list(for_uid))

def fuzzy_search(proc_list, search_str):
    search_str = search_str.lower()
    for entry in proc_list:
        match_str = []
        start = 0
        try:
            cmd_remain = entry["cmd_line"]
            for word in search_str.split():
                next_match = cmd_remain.lower().index(word.lower(), start)
                match_str += (cmd_remain[:next_match], Highlight(word))
                cmd_remain = cmd_remain[next_match+len(word):]
            match_str.append(cmd_remain)
            yield dict(entry, match_str=match_str)
        except ValueError:
            continue

def re_search(proc_list, regex):
    try:
        for entry in proc_list:
            match = re.search(regex, entry["cmd_line"], re.I)
            if match:
                match_str = (entry["cmd_line"][:match.start()], Highlight(match.group(0)), entry["cmd_line"][match.end():])
                yield dict(entry, match_str=match_str)
    except re.error:
        return


def generic_search(proc_list, inp):
    if inp and inp[0] == "/":
        try:
            return re_search(proc_list, inp[1:])
        except:
            return []
    else:
        return fuzzy_search(proc_list, inp)

def format_output(candidate, width=None, additional_format=""):
    global_format = u"%s%s" % (TEXT_DEFAULT, additional_format)
    match_str = []
    if candidate["owner"] != os.getuid():
        global_format = u"%s%s" % (TEXT_DEFAULT, TEXT_HALF_BRIGHT)
    n = 0
    for part in candidate["match_str"]:
        if width and n + len(part) > width - 9:
            match_str.append(part[:width - 9 - n])
            match_str.append(u"…")
            break
        n += len(part)
        if isinstance(part, Highlight):
            match_str += (TEXT_RED, part, global_format)
        else:
            match_str.append(part)
    return u"%s%5d %s" % (global_format, candidate["pid"], u"".join(match_str))

def get_term_size():
    height, width = struct.unpack('hh', fcntl.ioctl(sys.stdin.fileno(), termios.TIOCGWINSZ, '1234'))
    return width, height

def gentle_kill(candidates):
    for term_tries in range(2):
        for entry in candidates:
            try:
                os.kill(entry["pid"], signal.SIGTERM)
            except OSError as e:
                if e.errno == 3: # No such process
                    print("%s%s[%-5d]%s Was already gone: %s" % (TEXT_BOLD, TEXT_GREEN, entry["pid"], TEXT_DEFAULT, entry["cmd_line"]))
                else:
                    print("%s%s[%-5d]%s Failed to send SIGTERM to %s: %s" % (TEXT_BOLD, TEXT_RED, entry["pid"], TEXT_DEFAULT, entry["cmd_line"], e))
                candidates.remove(entry)

        alive = 0
        for i in range(50):
            if i == 10:
                if term_tries == 0:
                    print("%d process(es) still alive despite SIGTERM, giving them 5 seconds to react before sending it again" % len(candidates))
                else:
                    print("%d process(es) still alive despite SIGTERM, giving them 5 seconds to react before sending SIGKILL" % len(candidates))
            time.sleep(.1)
            alive = 0
            for entry in candidates:
                try:
                    os.kill(entry["pid"], 0)
                except OSError:
                    print("%s%s[%-5d]%s Killed %s" % (TEXT_BOLD, TEXT_GREEN, entry["pid"], TEXT_DEFAULT, entry["cmd_line"]))
                    candidates.remove(entry)
            if not candidates:
                break
        if not candidates:
            break

    if not candidates:
        return

    for entry in candidates:
        try:
            print("%s%s[%-5d]%s Sending SIGKILL to %s" % (TEXT_BOLD, TEXT_YELLOW, entry["pid"], TEXT_DEFAULT, entry["cmd_line"]))
            os.kill(entry["pid"], signal.SIGKILL)
        except OSError:
            if e.errno == 3: # No such process
                print("%s%s[%-5d]%s Was already gone: %s" % (TEXT_BOLD, TEXT_GREEN, entry["pid"], TEXT_DEFAULT, entry["cmd_line"]))
            else:
                print("%s%s[%-5d]%s Failed to send SIGKILL to %s: %s" % (TEXT_BOLD, TEXT_RED, entry["pid"], TEXT_DEFAULT, entry["cmd_line"], e))
            candidates.remove(entry)

    for i in range(50):
        time.sleep(.1)
        for entry in candidates:
            try:
                os.kill(entry["pid"], 0)
            except OSError:
                print("%s%s[%-5d]%s Killed %s" % (TEXT_BOLD, TEXT_GREEN, entry["pid"], TEXT_DEFAULT, entry["cmd_line"]))
                candidates.remove(entry)
                pass
        if not candidates:
            break

    if candidates:
        for entry in candidates:
            try:
                os.kill(entry["pid"], 0)
                print("%s%s[%-5d]%s Failed to SIGKILL %s" % (TEXT_BOLD, TEXT_RED, entry["pid"], TEXT_DEFAULT, entry["cmd_line"]))
            except OSError:
                pass

def main_interactive(proc_list=None, initial_inp=""):
    if not sys.stdout.isatty() or not sys.stdin.isatty():
        print("Interactive mode requires a TTY on stdin/stdout")
        return

    proc_list = proc_list or tuple(get_proc_lists(os.getuid()))
    inp = initial_inp

    sys.stdout.write("".join((TEXT_TO_ALTERNATE, TEXT_BOLD, ">>> ", TEXT_DEFAULT)))
    opts = termios.tcgetattr(sys.stdin.fileno())
    copts = termios.tcgetattr(sys.stdin.fileno())
    copts[3] = copts[3] & ~termios.ICANON & ~termios.ECHO
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, copts)
    candidates = []
    try:
        cand_text = ""
        selected = -1
        while True:
            cand_text = []
            candidates = []
            width, height = get_term_size()
            if inp:
                candidates = list(generic_search(proc_list, inp))
                if selected >= min(len(candidates), height - 3):
                    selected = min(len(candidates) - 1, height - 4)
                for n, candidate in enumerate(candidates):
                    cand_text.append(format_output(candidate, width, TEXT_BG_GREY if n == selected else ""))
                    if n == height - 4:
                        break
            cand_text = "\n".join(cand_text)

            sys.stdout.write("".join((TEXT_DEFAULT, TEXT_ERASE, TEXT_BOLD, ">>> ", TEXT_DEFAULT,
                                      inp if sys.version >= '3' else inp.encode(sys.getfilesystemencoding()),
                                      "\n", cand_text,
                                      "\033[%d;%dH" % (1, 5 + len(inp)))))
            sys.stdout.flush()

            if hasattr(sys.stdin, "buffer"):
                char = sys.stdin.buffer.read1(10).decode(sys.getfilesystemencoding())
            else:
                char = os.read(sys.stdin.fileno(), 10).decode(sys.getfilesystemencoding())
            if char == "\x7f":
                if inp:
                    inp = inp[:-1]
                selected = -1
            elif char == "\x1b":
                candidates = []
                break
            elif char[0] == "\x1b":
                # Escape sequence
                if char == "\x1b[A" and selected > -1: # Up
                    selected -= 1
                elif char == "\x1b[B": # Down
                    selected += 1
                pass
            elif char == "\n" or char == "\r":
                break
            else:
                selected = -1
                inp += char

    except KeyboardInterrupt:
        inp = ""
        candidates = []
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, opts)
        sys.stdout.write(TEXT_TO_NORMAL)
        sys.stdout.flush()

    if selected > -1:
        candidates = candidates[selected:selected+1]

    gentle_kill(candidates)

if __name__ == '__main__':
    if len(sys.argv) > 1:
        inp = " ".join(sys.argv[1:])
        proc_list = tuple(get_proc_lists(os.getuid()))
        candidates = list(generic_search(proc_list, inp))
        if len(candidates) < 2:
            gentle_kill(candidates)
        else:
            main_interactive(proc_list, inp)
    else:
        main_interactive()
