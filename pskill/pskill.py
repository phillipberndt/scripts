#!/usr/bin/env python
# encoding: utf-8
import fcntl
import os
import re
import signal
import struct
import sys
import termios
import time

TEXT_RED = "\033[31m"
TEXT_BOLD = "\033[1m"
TEXT_HALF_BRIGHT = "\033[2m"
TEXT_DEFAULT = "\033[0m"
TEXT_ERASE = "\033[H\033[J"
TEXT_TO_ALTERNATE = "\033[?1049h"
TEXT_TO_NORMAL = "\033[?1049l"
REQUEST_TERM_SIZE = "\033[18t"

class Highlight(str):
    pass

def get_proc_list(for_uid=None):
    for pid in os.listdir("/proc/"):
        cmd_file = os.path.join("/proc/", pid, "cmdline")
        if pid.isdigit() and os.access(cmd_file, os.R_OK):
            pid = int(pid)
            if pid == os.getpid():
                continue
            cmd_line = " ".join(('"%s"' % x.replace('"', r'\"') if " " in x else x.replace('"', r'\"') \
                                 for x in open(cmd_file).read().split("\0")))
            owner = os.stat(cmd_file).st_uid
            if for_uid is not None and for_uid != 0:
                if owner != for_uid:
                    continue
            yield {"pid": pid, "cmd_line": cmd_line, "owner": owner}

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
    for entry in proc_list:
        match = re.search(regex, entry["cmd_line"], re.I)
        if match:
            match_str = (entry["cmd_line"][:match.start()], Highlight(match.group(0)), entry["cmd_line"][match.end()+1:])
            yield dict(entry, match_str=match_str)


def format_output(candidate, width=None):
    global_format = TEXT_DEFAULT
    match_str = []
    if candidate["owner"] != os.getuid():
        global_format = "%s%s" % (TEXT_DEFAULT, TEXT_HALF_BRIGHT)
    n = 0
    for part in candidate["match_str"]:
        if width and n + len(part) > width - 9:
            match_str.append(part[:width - 9 - n])
            match_str.append("…")
            break
        n += len(part)
        if isinstance(part, Highlight):
            match_str += (TEXT_RED, part, global_format)
        else:
            match_str.append(part)
    return "%s%5d %s" % (global_format, candidate["pid"], "".join(match_str))

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
                    continue
                print("Failed to send SIGTERM to %s: %s" % (entry["cmd_line"], e))

        alive = 0
        for i in range(50):
            if i == 10:
                if term_tries == 0:
                    print("%d process(es) still alive despite SIGTERM, giving them 5 seconds to react before sending it again" % alive)
                else:
                    print("%d process(es) still alive despite SIGTERM, giving them 5 seconds to react before sending SIGKILL" % alive)
            time.sleep(.1)
            alive = 0
            for entry in candidates:
                try:
                    os.kill(entry["pid"], 0)
                    alive += 1
                except OSError:
                    pass
            if not alive:
                break
        if not alive:
            break

    if alive:
        for entry in candidates:
            try:
                print("Still alive, sending SIGKILL to %s" % entry["cmd_line"])
                os.kill(entry["pid"], signal.SIGKILL)
            except OSError:
                pass

    for i in range(50):
        time.sleep(.1)
        alive = 0
        for entry in candidates:
            try:
                os.kill(entry["pid"], 0)
                alive += 1
            except OSError:
                pass
        if not alive:
            break

    if alive:
        print()
        for entry in candidates:
            try:
                os.kill(entry["pid"], 0)
                print("Failed to kill %s" % entry["cmd_line"])
            except OSError:
                pass

def main():
    proc_list = tuple(get_proc_list(os.getuid()))

    sys.stdout.write("".join((TEXT_TO_ALTERNATE, TEXT_BOLD, ">>> ", TEXT_DEFAULT)))
    inp = ""
    opts = termios.tcgetattr(sys.stdin.fileno())
    copts = termios.tcgetattr(sys.stdin.fileno())
    copts[3] = copts[3] & ~termios.ICANON & ~termios.ECHO
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, copts)
    candidates = []
    try:
        cand_text = ""
        while True:
            sys.stdout.write("".join((TEXT_ERASE, TEXT_BOLD, ">>> ", TEXT_DEFAULT, inp, "\n", cand_text,
                                      "\033[%d;%dH" % (1, 5 + len(inp)))))
            sys.stdout.flush()
            if hasattr(sys.stdin, "buffer"):
                char = sys.stdin.buffer.read1(10).decode(sys.getfilesystemencoding())
            else:
                char = os.read(sys.stdin.fileno(), 10).decode(sys.getfilesystemencoding())
            if char == "\x7f":
                if inp:
                    inp = inp[:-1]
            elif char == "\x1b":
                candidates = []
                break
            elif char[0] == "\x1b":
                # Escape sequence
                # [A -> up
                # [B -> down
                # [C -> right
                # [D -> left
                pass
            elif char == "\n" or char == "\r":
                break
            else:
                inp += char

            candidates = []
            if inp:
                if inp[0] == "/":
                    try:
                        candidates += re_search(proc_list, inp[1:])
                    except:
                        pass
                else:
                    candidates += fuzzy_search(proc_list, inp)

            width, height = get_term_size()
            cand_text = "\n".join(( format_output(candidate, width) for n, candidate in enumerate(candidates) if n < height - 3)) if candidates else ""

    except KeyboardInterrupt:
        inp = ""
        candidates = []
    finally:
        termios.tcsetattr(sys.stdin.fileno(), termios.TCSANOW, opts)
        sys.stdout.write(TEXT_TO_NORMAL)
        sys.stdout.flush()

    gentle_kill(candidates)

if __name__ == '__main__':
    main()
