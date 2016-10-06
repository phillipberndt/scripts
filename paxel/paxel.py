#!/usr/bin/env python
# encoding: utf-8
"""
    pAxel - python axel(1) like program
    Copyright (c) 2016, Phillip Berndt

    TODO:
        * Command line options
        * Dynamically add/remove downloader threads based on download speed
        * Handle errors in indidivual downloader threads gracefully
        * Set output file mtime to the original file's mtime, if available

    This downloader uses the CurlMulti interface to let curl do all the work.
    CurlMulti is a single-threaded interface to curl allowing multiple parallel
    downloads. The program uses three of the callbacks offered by curl: One
    that is called once a header becomes available - this is used to determine
    whether ranged downloads are available. One that is called once data becomes
    available - this is used to _buffer_ this data in memory. Finally, one that
    is called quite often for progress reports. This is where the magic happens,
    i.e., where more downloaders are spawned, data is written to the output file,
    and so on. To monitor the download progress, this tool uses an interval set,
    that is, a data structure that is able to maintain an ordered set of closed
    intervals. Each download chunk is added to this set. If a chunk is to be
    written that is already contained in the set, then the download has obviously
    caught up to one that downloads one of the later parts of the file, and
    the download is aborted.

    Note that pycurl is set up such that if any of the callbacks returns a number
    that is unequal to the length of the data passed to the callback, a download
    is aborted.
"""
from __future__ import print_function
import argparse

import fcntl
import functools
import os
import shelve
import struct
import sys
import termios
import time

try:
    import pycurl
except:
    print("This program requires pycurl <http://pycurl.io/>", end="\n\n", file=sys.stderr)
    raise

__all__ = [ "IntervalSet", "download" ]

class IntervalSet(object):
    """ A set-like object that stores closed intervals.  """
    inf = float("inf")

    def __init__(self):
        self.contained = []

    def copy(self):
        ret = IntervalSet()
        ret.contained = self.contained[:]
        return ret

    def add(self, interval):
        # I have three possiblilities:
        # 1) The new interval does not intersect with another interval
        # 2) The new interval intersects with exactly one interval
        # 3) The new interval intersects with two intervals
        for index, (l, u) in enumerate(self.contained):
            if l - 1 > interval[1]:
                # The new interval is completely left from the current one
                self.contained.insert(index, interval)
                return
            if u + 1 < interval[0]:
                # The new interval is completely right from the current one
                continue
            # If I reach this point I know that the two intervals intersect
            if u >= interval[1]:
                # The new interval has a smaller upper bound than the current one
                # But I already know that there is no intersection in any of
                # the left intervals, so all is fine.
                self.contained[index] = (min(interval[0], l), u)
                return
            # The last remaining option is more complicated:
            # I know that the interval intersects, but I don't know yet if it also
            # intersects with the next one.  Maybe even more than one interval
            # needs to be merged.
            next_index = index + 1
            while next_index < len(self.contained) and self.contained[next_index][0] <= interval[1]:
                next_index += 1
            next_index -= 1

            self.contained[index] = (min(l, interval[0]), max(self.contained[next_index][1], interval[1]))
            del self.contained[index + 1:next_index + 1]
            return
        else:
            self.contained.append(interval)

    def remove(self, interval):
        index = 0
        while index < len(self.contained):
            l, u = self.contained[index]
            # old:      [....]
            # remove: [.........]
            if l >= interval[0] and u <= interval[1]:
                del self.contained[index]
                continue
            # old:     [....]
            # remove:          [.........]
            if u < interval[0]:
                pass
            # old:   [..............]
            # remove:   [.......]
            elif l <= interval[0] and u >= interval[1]:
                self.contained[index] = (interval[1] + 1, u)
                if interval[0] - 1 >= l:
                    self.contained.insert(index, (l, interval[0] - 1))
                    index += 1
            # old:   [....]
            # remove:  [.........]
            elif l <= interval[0] and u >= interval[0]:
                self.contained[index] = (l, interval[0] - 1)
            # old:             [....]
            # remove:  [.........]
            elif l <= interval[1] and u >= interval[1]:
                self.contained[index] = (interval[1] + 1, u)
            # old:                 [....]
            # remove:  [.........]
            else:
                break
            if self.contained[index][0] > self.contained[index][1]:
                del self.contained[index]
                continue
            index += 1

    def __str__(self):
        return str(self.contained)

    def __contains__(self, other):
        if type(other) is int:
            other = (other, other)
        for (l, u) in self.contained:
            if l <= other[0] and other[1] <= u:
                return True
        return False

    def contains(self, other):
        return other in self

    def overlaps(self, other):
        if type(other) is int:
            other = (other, other)
        for (l, u) in self.contained:
            if l <= other[0] or other[1] <= u:
                return True
        return False

    def __invert__(self):
        result = IntervalSet()
        result.add((-self.inf, self.inf))
        for iv in self.contained:
            result.remove(iv)
        return result

    def __add__(self, other):
        result = self.copy()
        for iv in other.contained:
            result.add(iv)
        return result

    def __sub__(self, other):
        result = self.copy()
        for iv in other.contained:
            result.remove(iv)
        return result


def header_callback(state, request_range, download, data):
    "cURL callback to process response headers. Full header in data."
    dl_state = state["parts"][download]

    if "range_ok" not in dl_state:
        if state["url"][:5].lower().startswith("ftp:"):
            # FTP always supports ranges, but has no real standardized way to
            # determine file sizes at this point. Let cURL sort that out.
            # (Reply 213 followed by bytes is a good guess though.)
            dl_state["range_ok"] = True
        else:
            data = data.lower()
            if "content-range" in data:
                dl_state["range_ok"] = True

                # Check if the server response matches the request
                range_type, range_data = data.split(":", 1)[1].strip().split()
                assert range_type == "bytes"
                range_bytes, range_total = range_data.split("/")

                response_min, response_max = range_bytes.split("-")
                request_min, request_max = request_range.split("-")

                assert (not request_min) or response_min == request_min
                assert (not request_max) or response_max == request_max

                dl_state["range_total"] = int(range_total)


class StateShelf(object):
    "A shelf that maintains some fixed keys in a local dict instead of in the shelf."
    _local_names = { "fd", "parts", "new_handles", "manager", "canceled", "fd_info_written" }


    def __init__(self, file_name):
        self._shelf = shelve.open(file_name, protocol=-1, writeback=True)
        self._locals = {}


    def __getitem__(self, name):
        if name in StateShelf._local_names:
            return self._locals[name]
        else:
            return self._shelf[name]


    def __contains__(self, name):
        if name in StateShelf._local_names:
            return name in self._locals
        else:
            return name in self._shelf


    def __setitem__(self, name, value):
        if name in StateShelf._local_names:
            self._locals[name] = value
        else:
            self._shelf[name] = value


    def __delitem__(self, name):
        if name in StateShelf._local_names:
            del self._locals[name]
        else:
            del self._shelf[name]


    def __nonzero__(self):
        return bool(self._locals) or bool(self._shelf)


    def update(self, dictionary):
        for key, value in dictionary.items():
            self[key] = value


    def sync(self):
        return self._shelf.sync()


def get_state_shelf(url, target_file=None):
    "Return an open shelf and a file name for the state file"
    state_template = "%s.paxel-state"
    if target_file:
        file_name = state_template % (target_file,)
    else:
        file_name = os.path.basename(url)
        if "?" in file_name:
            file_name = file_name[:file_name.find("?")]
        base, ext = os.path.splitext(file_name)
        candidates = [ x for x in os.listdir(".") if x.startswith(base) and x.endswith(state_template % (ext,)) ]
        if candidates:
            file_name = candidates[0]
        else:
            if not os.access(state_template % (file_name,), os.R_OK):
                file_name = state_template % (file_name,)
            else:
                counter = 0
                while os.access(state_template % ("%s.%d%s" % (base, counter, ext),), os.R_OK):
                    counter += 1
                file_name = state_template % ("%s.%d%s" % (base, counter, ext),)
    return StateShelf(file_name), file_name


def create_output_file(state):
    "Create the output file given a state dict, defined below."
    if state["target_file"]:
        file_name = state["target_file"]
    else:
        file_name = os.path.basename(state["url"])
        if "?" in file_name:
            file_name = file_name[:file_name.find("?")]
        if not file_name:
            file_name = "index"
        if os.access(file_name, os.R_OK):
            base, ext = os.path.splitext(file_name)
            counter = 0
            while os.access("%s.%d%s" % (base, counter, ext), os.R_OK):
                counter += 1
            file_name = "%s.%d%s" % (base, counter, ext)

    state["fd"] = open(file_name, "w")
    state["target_file"] = file_name

    if "file_size" in state and state["file_size"]:
        state["fd"].truncate(state["file_size"])


def spawn_downloaders(state):
    "Spawn downloader workers"
    chunk_size = state["file_size"] // 4
    file_pos = chunk_size
    for i in range(1, 4):
        gen_curl(state, "%d-%d" % (file_pos, (file_pos + chunk_size) if i < 3 else (state["file_size"] - 1)))
        file_pos += chunk_size


def format_file_size(num_bytes):
    "Return a human-readable file size."
    for hrn in [ "B", "KiB", "MiB", "GiB", "TiB" ]:
        if num_bytes < 1024:
            return "%.2f %s" % (num_bytes, hrn)
        num_bytes /= 1024.
    return "%e PiB" % (num_bytes)


def get_console_window_width():
    "Return the width of the tty"
    cr = struct.unpack('hh', fcntl.ioctl(1, termios.TIOCGWINSZ, '1234'))
    return cr[1]


def update_progress(state):
    "Display information on the progress of the download"

    if "fd" in state and "fd_info_written" not in state:
        error_output("Writing output to %s" % (state["target_file"]))
        state["fd_info_written"] = True

    # Update no more than once per second
    now = time.time()
    if "last_progress_update" in state and state["last_progress_update"] > now - 1:
        return
    state["last_progress_update"] = now

    if "file_size" in state and state["file_size"]:
        # Generate the progress bar
        cwidth = get_console_window_width()
        progress_bar_width = cwidth - 50

        progress_bits = state["file_size"] * 1. / progress_bar_width

        output = [ "\033[1m[\033[0;32m" ]
        for i in range(progress_bar_width):
            chunk = (progress_bits * i, progress_bits * (i+1) - 1)
            if chunk in state["done"]:
                # This part of the file is done
                output.append("-")
            else:
                # Is the beginning of a chunk contained in this part?
                for download, dl_state in state["parts"].items():
                    if chunk[0] <= dl_state["file_index"] < chunk[1]:
                        part_color_code = 32 # Green
                        if dl_state["speed"] < 1024:
                            part_color_code = 33 # Brown/Yellow
                        elif dl_state["speed"] < 10:
                            part_color_code = 31 # Red
                        output.append("\033[1;%dm>\033[22;32m" % (part_color_code,))
                        break
                else:
                    output.append(" ")

        output.append("\033[0;1m]\033[0m")
    else:
        output = [ "[..?..]" ]

    # Perform a few stats calculations
    if "stats" not in state:
        state["stats"] = { "done": [ (now, 0) ] }

    done = 0
    for l, u in state["done"].contained:
        done += u - l + 1

    if now - state["stats"]["done"][-1][0] > 1:
        state["stats"]["done"].append((now, done))
        if len(state["stats"]["done"]) > 5:
            state["stats"]["done"].pop(0)

    if len(state["stats"]["done"]) > 1:
        speed = (state["stats"]["done"][-1][1] - state["stats"]["done"][0][1]) * 1. / (state["stats"]["done"][-1][0] - state["stats"]["done"][0][0])
    else:
        speed = 0.

    hr_speed = "%s/s" % format_file_size(speed)
    percent_done = "%2.2f%%" % (done * 100. / state["file_size"],) if "file_size" in state else "?"
    hr_done = format_file_size(done)
    hr_size = format_file_size(state["file_size"]) if "file_size" in state else "?"

    sys.stdout.write("\033[u\r\033[s%s (%s %s/%s %s)\033[J" % ("".join(output), percent_done, hr_done, hr_size, hr_speed))
    sys.stdout.flush()


def flush_buffer(state, download):
    "Write all buffered data to the output file."
    if "fd" not in state:
        # Create the output file
        create_output_file(state)
    dl_state = state["parts"][download]
    while dl_state["buffer"]:
        data = dl_state["buffer"].pop(0)
        new_pos = dl_state["file_index"] + len(data)
        finished_chunk = (dl_state["file_index"], new_pos - 1)

        if finished_chunk in state["done"]:
            # Finished: This is something already downloaded somewhere else.
            return -1

        state["fd"].seek(dl_state["file_index"], 0)
        state["fd"].write(data)
        state["done"].add(finished_chunk)
        dl_state["file_index"] = new_pos


def progress_callback(state, request_range, download, download_total, download_done, upload_total, upload_done):
    "cURL callback for progress reports. Guaranteed to be called often. The main work-horse of this program."
    if "canceled" in state:
        return -2

    try:
        if download_total == 0 and download_done == 0:
            return

        try:
            dl_state = state["parts"][download]
        except KeyError:
            return -1

        if dl_state["buffer"]:
            # This means that there is data to be written to disk.

            if "file_size" not in state and len(state["parts"]) == 1 and download_total:
                # We are at the start of the download process and the total size of
                # the download is known. Spawn the other workers.
                state["file_size"] = download_total
                if "range_ok" in dl_state and dl_state["range_ok"]:
                    if "range_total" in dl_state and download_total != dl_state["range_total"]:
                        error_output("Warning: Content length %d and range length %d differ." % (download_total, dl_state["range_total"]))
                        state["file_size"] = max((download_total, dl_state["range_total"]))
                    spawn_downloaders(state)

            # Write output buffer to disk
            rsp = flush_buffer(state, download)
            if rsp is not None:
                dl_state["cancel_status"] = "deliberate"
                return rsp

        # Measure download speed
        now = time.time()
        if "done" not in dl_state:
            dl_state["done"] = [ (now, download_done) ]
        if now - dl_state["done"][-1][0] > 1:
            dl_state["done"].append((now, download_done))
            if len(dl_state["done"]) > 5:
                dl_state["done"].pop(0)
            dl_state["speed"] = (dl_state["done"][-1][1] - dl_state["done"][0][1]) * 1. / (dl_state["done"][-1][0] - dl_state["done"][0][0])

        update_progress(state)

    except KeyboardInterrupt:
        state["canceled"] = True
        return -2


def write_callback(state, request_range, download, data):
    """cURL callback invoked if data becomes available. Only stores the data to
    a buffer, it is written in the progress callback."""
    try:
        dl_state = state["parts"][download]
    except KeyError:
        return -1
    dl_state["buffer"].append(data)


def gen_curl(state, request_range=None):
    """Return a cURL easy instance for the download in the given state dict.

    The download is automatically added to the manager.

    If given, request_range must be a string "<lower end>-<upper end>", where
    the upper end is inclusive and either end can be omitted."""
    download = pycurl.Curl()
    download.setopt(pycurl.URL, state["url"])
    if request_range:
        download.setopt(pycurl.RANGE, request_range)
    download.setopt(pycurl.FOLLOWLOCATION, True)
    download.setopt(pycurl.HEADERFUNCTION, functools.partial(header_callback, state, request_range, download))
    download.setopt(pycurl.WRITEFUNCTION, functools.partial(write_callback, state, request_range, download))
    download.setopt(pycurl.XFERINFOFUNCTION, functools.partial(progress_callback, state, request_range, download))
    download.setopt(pycurl.NOPROGRESS, False)
    download.setopt(pycurl.LOW_SPEED_LIMIT, 1024)
    download.setopt(pycurl.LOW_SPEED_TIME, 30)
    download.setopt(pycurl.MAXREDIRS, 50)

    file_pos = 0
    range_upper = None
    if request_range:
        range_lower, range_upper = request_range.split("-")
        if range_lower:
            file_pos = int(range_lower)

    state["new_handles"].append(download)
    state["parts"][download] = { "buffer": [ ], "speed": 0, "chunk_start": file_pos, "chunk_end": range_upper, "file_index": file_pos }

    return download


def error_output(line):
    sys.stdout.write("\r%s\033[K\n\033[s" % (line,))
    sys.stdout.flush()


def download_loop_handle_info_read(state):
    queue_length, successful_downloads, failed_downloads = state["manager"].info_read()
    for download in successful_downloads:
        if download in state["parts"]:
            if state["parts"][download]["buffer"]:
                flush_buffer(state, download)
            del state["parts"][download]

    for download in failed_downloads:
        if download not in state["parts"]:
            continue
        dl_state = state["parts"][download]
        if dl_state["buffer"]:
            flush_buffer(state, download)
        if "cancel_status" in dl_state and dl_state["cancel_status"] == "deliberate":
            del state["parts"][download]
            continue
        else:
            errstr = download.errstr()
            if errstr:
                error_output("A part of the file failed to download: %s" % errstr)
            del state["parts"][download]

    # Check if there is a "gap" in the file and attempt to close it
    if "file_size" in state:
        covered = IntervalSet()
        covered.add((0, state["file_size"] - 1))
        left_over = covered - state["done"]
        for download, dl_state in state["parts"].items():
            left_over.remove((dl_state["chunk_start"], dl_state["chunk_end"]))
        for gap in left_over.contained:
            # These gaps won't be closed!
            gen_curl(state, "%d-%d" % (gap[0], gap[1]))


def download(url, target_file=None):
    "Download a file in parts, displaying progress. This function returns when the download is complete."
    sys.stdout.write("\033[s")

    manager = pycurl.CurlMulti()
    state, state_shelf_file_name = get_state_shelf(url, target_file)

    if state and "file_size" in state:
        # Continuation of earlier run
        state["parts"] = {}
        state["new_handles"] = []
        state["manager"] = manager
        state["fd"] = open(state["target_file"], "r+")
        download_loop_handle_info_read(state)
    else:
        state.update({ "parts": {}, "done": IntervalSet(), "url": url, "manager": manager, "new_handles": [], "target_file": target_file })
        gen_curl(state, "0-")

    # cURL main loop:
    # Handle cURL events and add new handles as they become available (they are
    # spawned above in the progress callback)
    while True:
        while state["new_handles"]:
            manager.add_handle(state["new_handles"].pop(0))
        ret, num_handles = manager.perform()
        download_loop_handle_info_read(state)
        if ret != pycurl.E_CALL_MULTI_PERFORM:
            break
    while num_handles or state["new_handles"]:
        update_progress(state)
        while state["new_handles"]:
            manager.add_handle(state["new_handles"].pop(0))
        if manager.select(1) == -1:
            continue
        while True:
            while state["new_handles"]:
                manager.add_handle(state["new_handles"].pop(0))
            ret, num_handles = manager.perform()
            download_loop_handle_info_read(state)
            if ret != pycurl.E_CALL_MULTI_PERFORM:
                break

    # Write remaining data
    for download in state["parts"]:
        flush_buffer(state, download)

    update_progress(state)
    if "fd" in state:
        state["fd"].close()
    state.sync()

    fail_state = False
    if "canceled" in state:
        # KeyboardInterrupt -- do not delete intermediates in this case.
        fail_state = True
    else:
        # Check for errors
        if "file_size" in state and state["file_size"]:
            covered = IntervalSet()
            covered.add((0, state["file_size"] - 1))
            left_over = covered - state["done"]
            if left_over.contained:
                print("\nSome parts of the file failed to download, namely bytes %s" % left_over)
                fail_state = True

        for download, dl_state in state["parts"].items():
            if "cancel_status" in dl_state and dl_state["cancel_status"] == "deliberate":
                continue
            errstr = download.errstr()
            if errstr:
                if not fail_state:
                    print
                print(errstr)
                fail_state = True

    if fail_state:
        bytes_written = sum([ b - a + 1 for a, b in state["done"].contained ])
        if not bytes_written:
            os.unlink(state["target_file"])
            del state
            os.unlink(state_shelf_file_name)
    else:
        error_output("Download finished.")
        del state
        os.unlink(state_shelf_file_name)

    return fail_state

if __name__ == "__main__":
    opts = argparse.ArgumentParser("paxel", description="A cURL based multi-downloader")
    opts.add_argument("url", metavar="url", type=str, help="The file to download")
    opts.add_argument("-o", metavar="file", help="Name of the output file", type=str, default=None)
    options = opts.parse_args()

    try:
        fail_state = download(options.url, options.o)
        if fail_state:
            error_output("Giving the download one retry..")
            fail_state = download(options.url, options.o)
            if fail_state:
                sys.exit(1)
        sys.exit(0)
    finally:
        print()
