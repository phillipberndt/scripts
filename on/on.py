#!/usr/bin/env python
# encoding: utf-8
import Queue
import datetime
import fnmatch
import getopt
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

global_output_lock = threading.RLock()

class EventBase(object):
    DESCRIPTION = "sample description"
    PREFIX = "sample"
    PARAMETER_DESCRIPTION = None

    def __init__(self, global_condition=None):
        self.event = threading.Event()
        self.reset_event = threading.Event()
        self.global_condition = global_condition
        self.setup()
        self.initialize()
        self.thread = threading.Thread(target=self.loop)
        self.thread.daemon = True
        self.thread.start()

    def setup(self):
        pass

    def initialize(self):
        pass

    def loop(self):
        while True:
            self.initialize()
            self.wait_for_event()
            self.event.set()
            if self.global_condition:
                with self.global_condition:
                    self.global_condition.notify()
            self.reset_event.wait()
            self.event.clear()
            self.reset_event.clear()

    def is_event_set(self):
        return self.event.is_set()

    def reset(self):
        if self.event.is_set():
            self.reset_event.set()

    def wait_for_event(self):
        raise NotImplementedError()

class OnEvent(EventBase):
    SUPPORTS_NEGATE = False

    def __init__(self, parameter, negate_condition=False, global_condition=None):
        if self.PARAMETER_DESCRIPTION is None and parameter is not None:
            raise ValueError("%s does not expect an argument" % self.__class__.__name__)
        self.negate_condition = negate_condition
        if self.negate_condition and not self.SUPPORTS_NEGATE:
            raise ValueError("%s does not support negation" % self.__class__.__name__)
        self.parameter = parameter
        super(OnEvent, self).__init__(global_condition=global_condition)

# Program exit {{{
class OnPIDExit(OnEvent):
    DESCRIPTION = "Wait for a program to exit"
    PREFIX = "exit"
    PARAMETER_DESCRIPTION = "pid|name"

    @staticmethod
    def is_alive(pid):
        return os.path.isdir("/proc/%d" % pid) and "zombie" not in open("/proc/%d/status" % pid).read()

    @staticmethod
    def pgrep(parameter):
        for pid in os.listdir("/proc"):
            if pid.isdigit():
                try:
                    cmdline = " ".join(('"%s"' % x if ' ' in x else x for x in open(os.path.join("/proc/", pid, "cmdline")).read().split("\0")))
                except IOError:
                    continue
                pid = int(pid)
                if pid == os.getpid():
                    continue
                if parameter in cmdline:
                    yield int(pid), cmdline

    def setup(self):
        parameter = self.parameter
        try:
            pid_list = [ int(parameter) ]
            if not OnPIDExit.is_alive(pid_list[0]):
                raise ValueError("PID %d does not belong to an existing process" % pid_list[0])
        except ValueError:
            processes = dict(OnPIDExit.pgrep(parameter))
            if str(os.getpid()) in processes:
                del processes[str(os.getpid())]
            if not processes:
                raise ValueError("No process matches `%s'" % parameter)
            with global_output_lock:
                if len(processes) > 1:
                    status(1, self.PREFIX, "Multiple choices: ")
                    for pid, proc in processes.items():
                        print "       %05s %s" % (pid, proc)
                    while True:
                        which = readline_timout("Which process do you want?", "all", 20, "^[0-9 ]+$")
                        if which == "all" or all(int(x) in processes for x in which.strip().split()):
                            break
                    if which != "all":
                        pid_list = [ int(x) for x in which.split() ]
                    else:
                        pid_list = map(int, processes.keys())
                else:
                    pid_list = [ int(processes.keys()[0]) ]
            status(0, self.PREFIX, "Waiting for any of %d processes to exit" % len(pid_list))
        self.pid_list = pid_list

    def wait_for_event(self):
        while True:
            for pid in self.pid_list:
                if not OnPIDExit.is_alive(pid):
                    status(0, self.PREFIX, "PID %d exited" % pid, True)
                    return
            time.sleep(1)
# }}}
# Inotify event {{{
try:
    import inotify.adapters
    has_inotify = True
except:
    has_inotify = False

if has_inotify:
    class OnFileChange(OnEvent):
        DESCRIPTION = "Wait for a file or directory to change"
        PREFIX = "inotify"
        PARAMETER_DESCRIPTION = "file"

        def setup(self):
            parameter = self.parameter
            self.ino = inotify.adapters.Inotify()

            self.globmatch = None
            if "*" in parameter:
                self.globmatch = parameter
                path = os.path.dirname(parameter.split("*", 1)[0]) or "."
                self.add_path(path)
                status(0, self.PREFIX, "Watching for %s in folder %s" % (parameter, path))
            else:
                self.add_path(parameter)
                status(0, self.PREFIX, "Watching for %s" % parameter)

            self.ino_queue = Queue.Queue()
            self.ino_thread = threading.Thread(target=self.__ino_consumer_thread)
            self.ino_thread.daemon = True
            self.ino_thread.start()

        def add_path(self, path):
            self.ino.add_watch(path, inotify.constants.IN_CLOSE_WRITE | inotify.constants.IN_CREATE)
            if os.path.isdir(path):
                for elem in os.listdir(path):
                    sub_path = os.path.join(path, elem)
                    if os.path.isdir(sub_path):
                        self.add_path(sub_path)

        def __ino_consumer_thread(self):
            for event in self.ino.event_gen():
                if event is not None:
                    header, type_names, fdir, filename = event
                    path = os.path.join(fdir, filename)
                    if self.globmatch is None or fnmatch.fnmatch(path, self.globmatch):
                        self.ino_queue.put(path)

        def initialize(self):
            while not self.ino_queue.empty():
                self.ino_queue.get()
                self.ino_queue.task_done()

        def wait_for_event(self):
            path = self.ino_queue.get()
            status(0, self.PREFIX, "%s updated" % path, True)
            self.ino_queue.task_done()
            return path
# }}}
# Network throughput {{{
class NetworkThroughput(OnEvent):
    DESCRIPTION = "Network throughput drops below a threshold"
    PREFIX = "nettput"
    PARAMETER_DESCRIPTION = "kiB/s"
    SUPPORTS_NEGATE = True

    @staticmethod
    def get_bytes():
        return sum(map(int, re.findall("[RT]X bytes:([0-9]+)", subprocess.check_output("ifconfig"))))

    def get_throughput(self):
        now = time.time()
        nbytes = self.get_bytes()
        throughput = (nbytes - self.nbytes) / (now - self.time)
        self.time = now
        self.nbytes = nbytes
        return throughput

    def setup(self):
        self.threshold = float(self.parameter) * 1024

    def initialize(self):
        self.nbytes = NetworkThroughput.get_bytes()
        self.time = time.time()
        time.sleep(1)
        status(0, self.PREFIX, "Startup throughput is %2.2f kiB/s" % (self.get_throughput() / 1024, ))

    def wait_for_event(self):
        while True:
            time.sleep(10)
            throughput = self.get_throughput()
            status(0, self.PREFIX, "Throughput is %2.2f kiB/s" % (throughput / 1024, ), True)
            if self.negate_condition:
                if throughput >= self.threshold:
                    break
            else:
                if throughput < self.threshold:
                    break
# }}}
# Ping {{{
class Pingable(OnEvent):
    DESCRIPTION = "Host replies to ping"
    PREFIX = "ping"
    PARAMETER_DESCRIPTION = "remote host"
    SUPPORTS_NEGATE = True

    def setup(self):
        self.parameter = self.parameter or "8.8.8.8"

    def wait_for_event(self):
        status(0, self.PREFIX, "Trying to ping %s" % self.parameter)
        with open("/dev/null", "w") as null:
            spinner = "|/-\\"
            n = 0
            while True:
                n += 1
                if subprocess.call(["ping", "-c", "1", "-W", "5", self.parameter], stdout=null, stderr=null) == 0:
                    status(0, self.PREFIX, "Received ping reply from %s [%c]" % (self.parameter, spinner[n%len(spinner)]), True)
                    if not self.negate_condition:
                        break
                    time.sleep(5)
                else:
                    status(0, self.PREFIX, "Didn't receive a ping reply from %s [%c]" % (self.parameter, spinner[n%len(spinner)]), True)
                    if self.negate_condition:
                        break
# }}}
# Socket connection {{{
class SocketConnection(OnEvent):
    DESCRIPTION = "Network connection to host is closed"
    PREFIX = "tcpconn"
    PARAMETER_DESCRIPTION = "remote host"
    SUPPORTS_NEGATE = True

    @staticmethod
    def get_connections():
        with open("/proc/net/tcp") as tcp_file:
            for line in tcp_file.readlines():
                data = line.split()
                if data[3] == "01": # TCP_ESTABLISHED
                    host, port = data[2].split(":")
                    port = int(port, 16)
                    ip = socket.inet_ntoa(struct.pack("@I", int(host, 16)))
                    yield ip, port
        with open("/proc/net/tcp6") as tcp6_file:
            for line in tcp6_file.readlines():
                data = line.split()
                if data[3] == "01": # TCP_ESTABLISHED
                    host, port = data[2].split(":")
                    port = int(port, 16)
                    ip = socket.inet_ntop(socket.AF_INET6, struct.pack("@IIII", int(host[:4], 16), int(host[4:8], 16), int(host[8:12], 16), int(host[12:], 16)))
                    yield ip, port

    def setup(self):
        parameter = self.parameter
        via = ""
        if re.match("^[0-9\.:]+$", parameter):
            self.ip = parameter
        else:
            if self.negate_condition:
                raise ValueError("%s can only be negated if the argument is an IP" % (self.PREFIX,))
            try:
                ips = socket.gethostbyaddr(parameter)[2]
            except socket.gaierror:
                ips = []
            for ip in ips:
                if ip in (x[0] for x in SocketConnection.get_connections()):
                    via = "via DNS resolution"
                    self.ip = ip
                    break
            else:
                for ip, port in self.get_connections():
                    host = socket.gethostbyaddr(ip)
                    if parameter in host[0]:
                        via = "reversely via %s:%d" % (host[0], port)
                        self.ip = ip
                        break
                else:
                    raise ValueError("No open connection to %s found" % parameter)
        status(0, self.PREFIX, "Waiting for connection(s) to %s to be closed%s" % (self.ip, (" (found %s)" % via) if via else ""))

    def wait_for_event(self):
        if self.negate_condition:
            while self.ip not in (x[0] for x in SocketConnection.get_connections()):
                time.sleep(1)
        else:
            while self.ip in (x[0] for x in SocketConnection.get_connections()):
                time.sleep(1)

# }}}
# Timer {{{
class Timer(OnEvent):
    DESCRIPTION = "Wait for a specific amount of time, like sleep"
    PREFIX = "timer"
    PARAMETER_DESCRIPTION = "time"

    TIME_SYNTAX = re.compile("(?P<at>@?)(?P<hour>[0-9]{1,2}):(?P<minute>[0-9]{1,2})(?:(?P<second>[0-9]{1,2}))?")

    def setup(self):
        self.time_seconds = 0

        for match in Timer.TIME_SYNTAX.finditer(self.parameter):
            if match.group("at"):
                now = datetime.datetime.now()
                wait_until = datetime.datetime.combine(now,
                    datetime.time(int(match.group("hour")), int(match.group("minute")), int(match.group("second") or 0)))
                self.time_seconds += (wait_until - now).total_seconds()
            else:
                self.time_seconds += int(match.group("hour")) * 3600 + int(match.group("minute")) * 60 + int(match.group("second") or 0)
        self.parameter = Timer.TIME_SYNTAX.sub("", self.parameter)

        to_seconds = { "d": 3600*24, "h": 3600, "m": 60, "s": 1, "": 1 }
        for amount, unit in re.findall("([0-9\.]+)([hms]?)", self.parameter):
            self.time_seconds += float(amount) * to_seconds[unit]

    def wait_for_event(self):
        wait_until = datetime.datetime.now() + datetime.timedelta(seconds=self.time_seconds)
        status(0, self.PREFIX, "Waiting until %s" % (wait_until.isoformat(),))
        while True:
            time_to_wait = (wait_until - datetime.datetime.now()).total_seconds() + 1
            if time_to_wait < 0:
                break
            status(0, self.PREFIX, "Waiting until %s (%s left)" % (wait_until.isoformat(), seconds_to_time(time_to_wait)), True)
            time.sleep(time_to_wait if time_to_wait < 5 else 5)
# }}}
# CPU usage {{{
class CPUUsage(OnEvent):
    DESCRIPTION = "CPU usage drops below a threshold"
    PREFIX = "cpu"
    PARAMETER_DESCRIPTION = "percent"
    SUPPORTS_NEGATE = True

    @staticmethod
    def get_stat():
        stat  = open("/proc/stat").readline().split()
        assert stat[0] == "cpu"
        user, nice, system, idle = stat[1:5]
        work_time = int(user) + int(nice) + int(system)
        return work_time, work_time + int(idle)

    def get_usage(self):
        stat = CPUUsage.get_stat()
        usage = (stat[0] - self.stat[0]) * 100. / (stat[1] - self.stat[1])
        self.stat = stat
        return usage

    def setup(self):
        self.threshold = float(self.parameter)

    def initialize(self):
        self.stat = CPUUsage.get_stat()
        time.sleep(1)
        status(0, self.PREFIX, "Startup CPU usage is %2.2f%%" % (self.get_usage(),))

    def wait_for_event(self):
        while True:
            time.sleep(1)
            try:
                usage = self.get_usage()
            except ZeroDivisionError:
                continue
            status(0, self.PREFIX, "CPU usage is %2.2f%%" % (usage,), True)
            if (usage < self.threshold) != self.negate_condition:
                break
# }}}
# MEM usage {{{
class MEMUsage(OnEvent):
    DESCRIPTION = "Memory usage drops below a threshold"
    PREFIX = "mem"
    PARAMETER_DESCRIPTION = "percent"
    SUPPORTS_NEGATE = True

    @staticmethod
    def get_meminfo():
        data = {}
        for line in open("/proc/meminfo").readlines():
            key, value = line.split(":", 1)
            value = int(value.strip().split()[0])
            data[key] = value
        return data

    def get_usage(self):
        data = MEMUsage.get_meminfo()
        return 100 - 100. * (data["MemFree"] + data["Cached"] + data["Buffers"]) / data["MemTotal"]

    def setup(self):
        self.meminfo = MEMUsage.get_meminfo()
        self.threshold = float(self.parameter)

    def initialize(self):
        usage = self.get_usage()
        status(0, self.PREFIX, "Startup mem usage is %2.2f%% (%d MiB)" % (usage, usage / 100 / 1024 * self.meminfo["MemTotal"]))

    def wait_for_event(self):
        while True:
            time.sleep(1)
            usage = self.get_usage()
            status(0, self.PREFIX, "mem usage is %2.2f%% (%d MiB)" % (usage, usage / 100 / 1024 * self.meminfo["MemTotal"]), True)
            if (usage < self.threshold) != self.negate_condition:
                break
# }}}
# Movement {{{
try:
    import cv2
    has_opencv = True
except:
    has_opencv = False
if has_opencv:
    class Movement(OnEvent):
        DESCRIPTION = "Detect movement on the webcam"
        PREFIX = "movement"
        SUPPORTS_NEGATE = True

        def setup(self):
            with SupressOutput():
                self.cam = cv2.VideoCapture(0)
            status(0, self.PREFIX, "Waiting for movement")

        def grab_frame(self):
            frame = self.cam.read()[1]
            while frame is None:
                with SupressOutput():
                    self.cam = cv2.VideoCapture(0)
                frame = self.cam.read()[1]
            frame = cv2.cvtColor(frame, cv2.COLOR_RGB2GRAY)
            return frame

        def wait_for_event(self):
            while True:
                for i in range(10):
                    frame = self.grab_frame()
                maxVal = 0
                while True:
                    new_frame = self.grab_frame()
                    diff = cv2.absdiff(cv2.GaussianBlur(frame, (21, 21), 0), cv2.GaussianBlur(new_frame, (21, 21), 0))
                    frame = new_frame
                    (minVal, maxVal, minLoc, maxLoc) = cv2.minMaxLoc(diff)
                    status(0, self.PREFIX, "Movement level is %2d" % maxVal, True)
                    if (maxVal < 60) == self.negate_condition:
                        break
                return True
# }}}
# Whistling {{{
try:
    import alsaaudio
    has_alsa = True
except:
    has_alsa = False
try:
    import numpy
    has_numpy = True
except:
    has_numpy = False
if has_alsa and has_numpy:
    class Whistle(OnEvent):
        DESCRIPTION = "Detect whistling on the primary microphone"
        PREFIX = "whistle"
        SUPPORTS_NEGATE = True

        def setup(self):
            self.pcm = alsaaudio.PCM(alsaaudio.PCM_CAPTURE)
            self.pcm.setformat(alsaaudio.PCM_FORMAT_FLOAT_LE)
            self.pcm.setrate(16000)
            self.pcm.setchannels(1)

        def initialize(self):
            status(0, self.PREFIX, "Waiting for a whistle")

        def get_center_freq(self):
            data = []
            for i in range(50):
                length, sdata = self.pcm.read()
                data.append(numpy.fromstring(sdata, dtype='float'))
            data = numpy.hstack(data)
            data = data * numpy.hanning(data.size)
            fdata = numpy.fft.rfft(data)
            freqs = numpy.fft.rfftfreq(data.size, d=1./16000)
            A = numpy.log10(max(fdata)).real
            f = freqs[numpy.argmax(fdata)]
            return f, A

        def wait_for_event(self):
            while True:
                f, A = self.get_center_freq()
                if A > -7:
                    if f < 1e3:
                        status(0, self.PREFIX, "Center frequency %04.2f Hz is uninteresting" % f, True)
                    else:
                        time.sleep(.1)
                        f2, A2 = self.get_center_freq()
                        if abs(f - f2) > .5e3:
                            status(1, self.PREFIX, "No whistle, %04.2f Hz fits but too short" % f, True)
                        else:
                            status(0, self.PREFIX, "Got a whistle at %04.2f Hz with amplitude %03.2f" % (f, A), True)
                            if not self.negate_condition:
                                return True
                            else:
                                continue
                if self.negate_condition:
                    return True
# }}}

def print_help():
    print "Execute a program once a certain event occurs"
    print "Syntax: on [-krw] <type>[:<arguments>] <type>[:<arguments>] .. [--] [sudo] <action>"
    print
    print "Options:"
    print "  -k   Kill old action if it is retriggered too fast"
    print "  -r   Repeat action"
    print "  -w   Wait for action to complete before running it again"
    print "  -o   Neatly format the action's output"
    print "  -a   If multiple events are given, AND them instead of ORing"
    print
    print "Event types:"
    for cls in sorted(OnEvent.__subclasses__(), key=lambda x: x.PREFIX):
        print "  %3s%-25s %s" % ("[~]" if cls.SUPPORTS_NEGATE else "", "%s:<%s>" % (cls.PREFIX, cls.PARAMETER_DESCRIPTION) if cls.PARAMETER_DESCRIPTION else cls.PREFIX, cls.DESCRIPTION)
    print "An ampersand negates an event's meaning."
    print

global_status_info_cache = []
last_index = [ 0 ]
def status(level, component, line, is_update=False):
    with global_output_lock:
        if level == 0:
            col = "32"
        elif level == 1:
            col = "33"
        else:
            col = "31"

        try:
            index = global_status_info_cache.index(component)
            if not is_update:
                while global_status_info_cache:
                    global_status_info_cache.pop()
                global_status_info_cache.append(component)
                index = 0
                last_index[0] = 0
        except ValueError:
            global_status_info_cache.append(component)
            index = len(global_status_info_cache) - 1

        movement = index - last_index[0]
        last_index[0] = index + 1

        print "%s\033[K[\033[1;%sm%s\033[0m] %s" % (("\033[%dA" % -movement) if movement < 0 else ("\033[%dB" % movement) if movement > 0 else "", col, component, line)

def readline_timout(query, default, timeout=0, expect=None):
    with global_output_lock:
        class _TimeoutError(Exception):
            pass
        def _raise(*args):
            raise _TimeoutError()
        _old = signal.signal(signal.SIGALRM, _raise)
        try:
            while True:
                if timeout:
                    signal.alarm(timeout)
                data = raw_input("\007\033[1m%s\033[0m [%s, %ds timeout]: " % (query, default, timeout)).strip()
                if not data:
                    return default
                if not expect or re.match(expect, data):
                    return data
                print "\033[1F\033[K",
        except _TimeoutError:
            print
            return default
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, _old)

def is_executable(file_name):
    for path in os.environ["PATH"].split(":"):
        if os.access(os.path.join(path, file_name), os.X_OK | os.F_OK):
            return True
    return False

def seconds_to_time(seconds):
    output = []
    if seconds > 3600:
        output.append("%02d" % (seconds // 3600,))
        seconds %= 3600
    output.append("%02d" % (seconds // 60,))
    seconds %= 60
    output.append("%02d" % seconds)
    return ":".join(output)

class SupressOutput(object):
    def __enter__(self):
        global_output_lock.acquire()
        self.stdout_fd = sys.stdout.fileno()
        self.stderr_fd = sys.stderr.fileno()
        self.stdout_dup = os.dup(self.stdout_fd)
        self.stderr_dup = os.dup(self.stderr_fd)
        self.null = open("/dev/null", "r+")
        os.dup2(self.null.fileno(), self.stdout_fd)
        os.dup2(self.null.fileno(), self.stderr_fd)

    def __exit__(self, type, value, traceback):
        os.dup2(self.stdout_dup, self.stdout_fd)
        os.dup2(self.stderr_dup, self.stderr_fd)
        os.close(self.stdout_dup)
        os.close(self.stderr_dup)
        global_output_lock.release()

def format_output_thread(proc):
    class Quit(Exception):
        pass

    stdout = proc.stdout
    stderr = proc.stderr

    bufs = ["", ""]
    def _pbufs(force):
        for idn, out in enumerate((stdout, stderr)):
            if "\n" in bufs[idn]:
                lines = bufs[idn].split("\n")
                if not force:
                    bufs[idn] = lines.pop()
                for line in lines:
                    print "\033[0;%dm>>>\033[0m" % (32 if out is stdout else 31), line

    try:
        while True:
            rlist, _, _ = select.select((stdout, stderr), (), ())
            for idn, out in enumerate((stdout, stderr)):
                if out in rlist:
                    read = os.read(out.fileno(), 1024**2)
                    if not read:
                        raise Quit()
                    bufs[idn] += read
                    _pbufs(False)
    except Quit:
        _pbufs(True)
        if proc.wait() == 0:
            status(0, "on", "Program has exited.")
        else:
            status(1, "on", "Program exited with code %d" % (proc.returncode,))

def init_sudo(sudo_executable):
    status(0, "sudo", "Pre-authenticating for command involving sudo")
    subprocess.call([sudo_executable, "-v"])
    status(0, "sudo", "Authenticated for command involving sudo")
    def _sudo_thread():
        while True:
            time.sleep(60 * 4)
            subprocess.call([sudo_executable, "-nv"])
            status(0, "sudo", "Renewed sudo authentication at %s" % (datetime.datetime.now().isoformat(),), True)
    sudo_thread = threading.Thread(target=_sudo_thread)
    sudo_thread.daemon = True
    sudo_thread.start()

_setsid_popen_tty = os.ttyname(0)

def preexec_fn():
    os.setpgid(0, 0)
    # Do not use setsid because that kills sudo's sudoers cache support!

def main():
    events = []

    try:
        opts, args = getopt.getopt(sys.argv[1:], "krwoa")
        opts = dict(opts)

        while args and args[0] != "--":
            event = args[0]
            parameter = None
            if ":" in event:
                event, parameter = event.split(":", 1)

            if event and event[0] == "~":
                negate = True
                event = event[1:]
            else:
                negate = False

            handler = None
            for cls in OnEvent.__subclasses__():
                if cls.PREFIX == event:
                    handler = cls
                    break

            if handler:
                events.append((handler, parameter, negate))
                args.pop(0)
            else:
                break

        if args and args[0] == "--":
            args.pop(0)

        action = args
        assert events
    except:
        print_help()
        sys.exit(1)

    if action and "sudo" in action[0]:
        init_sudo(action[0])

    global_condition = threading.Condition(threading.RLock())
    event_objects = []
    for handler, parameter, negate_condition in events:
        instance = handler(parameter, negate_condition=negate_condition, global_condition=global_condition)
        event_objects.append(instance)

    ptarget = subprocess.PIPE if "-o" in opts else None
    proc = None
    while True:
        global_condition.acquire()
        global_condition.wait(99999) # timeout required for C-c to work in Py 2.x, see python issue 8844
        condition_met = (all if "-a" in opts else any)(( x.is_event_set() for x in event_objects ))
        global_condition.release()
        if not condition_met:
            continue

        if "-k" in opts and proc:
            if proc.poll() is None:
                status(1, "on", "Killing old action instance %d" % proc.pid)
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.terminate()
                proc.wait()
        if action:
            if is_executable(action[0]):
                proc = subprocess.Popen(action, stdout=ptarget, stderr=ptarget, preexec_fn=preexec_fn)
            else:
                proc = subprocess.Popen(action, shell=True, stdout=ptarget, stderr=ptarget, preexec_fn=preexec_fn)
            if ptarget:
                proc_thread = threading.Thread(target=format_output_thread, args=(proc, ))
                proc_thread.start()
                if "-w" in opts:
                    proc.wait()
            else:
                if "-w" in opts:
                    proc.communicate()
        if "-r" not in opts:
            break

        global_condition.acquire()
        for x in event_objects:
            x.reset()
        global_condition.release()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
