#!/usr/bin/env python3
# Interactive fuzzy process killer.
from __future__ import annotations

import fcntl
import os
import re
import shutil
import signal
import struct
import sys
import termios
import time
from dataclasses import dataclass, field, replace

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"
CLEAR = "\033[H\033[J"
ALT_SCREEN_ON = "\033[?1049h"
ALT_SCREEN_OFF = "\033[?1049l"
SELECTED_BG = "\033[47m"

# A SIGTERM is sent, then we poll this many 0.1s ticks for the process to
# exit before escalating. 50 ticks == 5 seconds.
GRACE_TICKS = 50


@dataclass
class Proc:
    pid: int
    cmdline: str
    uid: int
    # Spans of the cmdline that matched the query, as (start, end) index
    # pairs into `cmdline`. Rendered highlighted.
    matches: list[tuple[int, int]] = field(default_factory=list)


def _read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as fh:
        return fh.read()


def read_proc(pid: int) -> Proc | None:
    """Build a Proc from /proc/<pid>, or None if it vanished or is unreadable."""
    try:
        raw = _read(f"/proc/{pid}/cmdline")
        # /proc/<pid>/cmdline is NUL-separated and NUL-terminated. Kernel
        # threads expose an empty cmdline; fall back to comm in brackets.
        args = [a for a in raw.split("\0") if a]
        if args:
            cmdline = " ".join(f'"{a}"' if " " in a else a for a in args)
        else:
            cmdline = "[%s]" % _read(f"/proc/{pid}/comm").strip()
        uid = os.stat(f"/proc/{pid}").st_uid
    except (FileNotFoundError, ProcessLookupError, PermissionError):
        return None
    return Proc(pid=pid, cmdline=cmdline, uid=uid)


def ancestor_pids() -> set[int]:
    """PIDs of this process and all its ancestors, which must never be killed."""
    protected = set()
    pid = os.getpid()
    while pid > 0 and pid not in protected:
        protected.add(pid)
        try:
            # Field 4 of /proc/<pid>/stat is PPid. comm (field 2) may contain
            # spaces/parens, so split after the last ")".
            stat = _read(f"/proc/{pid}/stat")
            pid = int(stat[stat.rindex(")") + 2:].split()[1])
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError):
            break
    return protected


def list_procs(for_uid: int | None) -> list[Proc]:
    protected = ancestor_pids()
    out = []
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid in protected:
            continue
        proc = read_proc(pid)
        if proc is None:
            continue
        if for_uid is None or proc.uid == for_uid:
            out.append(proc)
    return out


def fuzzy_search(procs: list[Proc], query: str) -> list[Proc]:
    """Match each query word as a substring, left to right, case-insensitive."""
    words = query.lower().split()
    results = []
    for proc in procs:
        hay = proc.cmdline.lower()
        pos = 0
        spans = []
        for word in words:
            found = hay.find(word, pos)
            if found < 0:
                break
            spans.append((found, found + len(word)))
            pos = found + len(word)
        else:
            results.append(replace(proc, matches=spans))
    return results


def regex_search(procs: list[Proc], pattern: str) -> list[Proc]:
    try:
        rx = re.compile(pattern, re.I)
    except re.error:
        return []
    results = []
    for proc in procs:
        m = rx.search(proc.cmdline)
        if m:
            results.append(replace(proc, matches=[(m.start(), m.end())]))
    return results


def search(procs: list[Proc], query: str) -> list[Proc]:
    if query.startswith("/"):
        return regex_search(procs, query[1:])
    return fuzzy_search(procs, query)


def format_proc(proc: Proc, width: int, highlight_bg: str = "") -> str:
    base = RESET + (DIM if proc.uid != os.getuid() else highlight_bg)
    budget = width - 7  # 6 for the pid column, 1 for the gap
    out = [base]
    rendered = 0
    cursor = 0
    for start, end in proc.matches:
        for seg, color in ((proc.cmdline[cursor:start], base),
                            (proc.cmdline[start:end], RED)):
            if rendered + len(seg) > budget:
                out.append(color + seg[:budget - rendered] + "…")
                rendered = budget + 1
                break
            out.append(color + seg)
            rendered += len(seg)
        else:
            cursor = end
            continue
        break
    else:
        tail = proc.cmdline[cursor:]
        if rendered + len(tail) > budget:
            tail = tail[:budget - rendered] + "…"
        out.append(base + tail)
    out.append(RESET)
    return f"{base}{proc.pid:5d} {''.join(out)}"


def term_size() -> tuple[int, int]:
    try:
        packed = fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ, b"\0" * 8)
        rows, cols = struct.unpack("hhhh", packed)[:2]
        if cols and rows:
            return cols, rows
    except OSError:
        pass
    size = shutil.get_terminal_size((80, 24))
    return size.columns, size.lines


def _poll_exits(targets: list[Proc], ticks: int) -> None:
    """Poll up to `ticks` 0.1s intervals, printing and dropping exited targets."""
    for _ in range(ticks):
        if not targets:
            return
        time.sleep(0.1)
        for proc in list(targets):
            if not pid_alive(proc.pid):
                print(f"{BOLD}{GREEN}[{proc.pid:-5d}]{RESET} Killed {proc.cmdline}")
                targets.remove(proc)


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    # Signal 0 succeeds on zombies (exited but not yet reaped by their
    # parent). Treat those as dead so kill reporting is accurate even when
    # a target happens to be our own child.
    try:
        stat = _read(f"/proc/{pid}/stat")
        state = stat[stat.rindex(")") + 2:].split()[0]
        return state != "Z"
    except (FileNotFoundError, ProcessLookupError, ValueError, IndexError):
        return False


def gentle_kill(targets: list[Proc]) -> None:
    targets = list(targets)
    if not targets:
        return

    for attempt in range(2):
        for proc in list(targets):
            try:
                os.kill(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                print(f"{BOLD}{GREEN}[{proc.pid:-5d}]{RESET} Was already gone: {proc.cmdline}")
                targets.remove(proc)
            except OSError as e:
                print(f"{BOLD}{RED}[{proc.pid:-5d}]{RESET} Failed to send SIGTERM to {proc.cmdline}: {e}")
                targets.remove(proc)

        if not targets:
            return
        tail = "sending it again" if attempt == 0 else "sending SIGKILL"
        print(f"{len(targets)} process(es) still alive after SIGTERM, "
              f"waiting {GRACE_TICKS // 10}s before {tail}")
        _poll_exits(targets, GRACE_TICKS)
        if not targets:
            return

    for proc in list(targets):
        try:
            print(f"{BOLD}{YELLOW}[{proc.pid:-5d}]{RESET} Sending SIGKILL to {proc.cmdline}")
            os.kill(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            print(f"{BOLD}{GREEN}[{proc.pid:-5d}]{RESET} Was already gone: {proc.cmdline}")
            targets.remove(proc)
        except OSError as e:
            print(f"{BOLD}{RED}[{proc.pid:-5d}]{RESET} Failed to send SIGKILL to {proc.cmdline}: {e}")
            targets.remove(proc)

    _poll_exits(targets, GRACE_TICKS)
    for proc in targets:
        if pid_alive(proc.pid):
            print(f"{BOLD}{RED}[{proc.pid:-5d}]{RESET} Failed to SIGKILL {proc.cmdline}")


def run_ui(procs: list[Proc], initial: str = "") -> list[Proc]:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Interactive mode requires a TTY on stdin/stdout")
        return []

    query = initial
    selected = -1
    chosen: list[Proc] = []
    fd = sys.stdin.fileno()
    saved = termios.tcgetattr(fd)
    raw = termios.tcgetattr(fd)
    raw[3] &= ~termios.ICANON & ~termios.ECHO
    termios.tcsetattr(fd, termios.TCSANOW, raw)
    sys.stdout.write(ALT_SCREEN_ON)
    try:
        while True:
            width, height = term_size()
            max_rows = max(height - 2, 1)
            candidates = search(procs, query) if query else []
            if selected >= min(len(candidates), max_rows):
                selected = min(len(candidates), max_rows) - 1

            lines = [
                format_proc(c, width, SELECTED_BG if i == selected else "")
                for i, c in enumerate(candidates[:max_rows])
            ]
            sys.stdout.write(
                RESET + CLEAR + BOLD + ">>> " + RESET + query + "\n"
                + "\n".join(lines)
                + f"\033[1;{5 + len(query)}H"
            )
            sys.stdout.flush()

            char = os.read(fd, 16).decode(sys.getfilesystemencoding(), "replace")
            if char in ("\n", "\r"):
                if selected > -1 and selected < len(candidates):
                    chosen = [candidates[selected]]
                else:
                    chosen = candidates
                break
            if char == "\x7f":  # Backspace
                query = query[:-1]
                selected = -1
            elif char == "\x1b":  # Bare Escape: abort
                break
            elif char == "\x1b[A":  # Up
                selected = max(selected - 1, -1)
            elif char == "\x1b[B":  # Down
                selected += 1
            elif char.startswith("\x1b"):
                pass  # ignore other escape sequences
            elif char.isprintable():
                query += char
                selected = -1
    except KeyboardInterrupt:
        chosen = []
    finally:
        termios.tcsetattr(fd, termios.TCSANOW, saved)
        sys.stdout.write(ALT_SCREEN_OFF)
        sys.stdout.flush()
    return chosen


def main(argv: list[str]) -> int:
    procs = list_procs(os.getuid())
    if len(argv) > 1:
        query = " ".join(argv[1:])
        candidates = search(procs, query)
        if len(candidates) < 2:
            gentle_kill(candidates)
        else:
            gentle_kill(run_ui(procs, query))
    else:
        gentle_kill(run_ui(procs))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
