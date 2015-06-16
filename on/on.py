#!/usr/bin/env python
# encoding: utf-8
import getopt
import glob
import os
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import time
import threading

class OnEvent(object):
    DESCRIPTION = "sample description"
    PREFIX = "sample"
    PARAMETER_DESCRIPTION = None

    def __init__(self, parameter):
        if self.PARAMETER_DESCRIPTION is None and parameter is not None:
            raise ValueError("%s does not expect an argument" % self.__class__.__name__)
        self.parameter = parameter

    def wait_for_event(self):
        raise NotImplementedError()

class Modifier(object):
    DESCRIPTION = "sample modifier"
    PREFIX = "~"

    def __init__(self, event_handler, parameter):
        self.event_handler = event_handler
        self.parameter = parameter

    def wait_for_event(self):
        raise NotImplementedError()

# Program exit {{{
class OnPIDExit(OnEvent):
    DESCRIPTION = "Wait for a program to exit"
    PREFIX = "exit"
    PARAMETER_DESCRIPTION = "pid|name"

    @staticmethod
    def is_alive(pid):
        return os.path.isdir("/proc/%d" % pid) and "zombie" not in open("/proc/%d/status" % pid).read()

    def __init__(self, parameter):
        try:
            pid_list = [ int(parameter) ]
            if not OnPIDExit.is_alive(pid_list[0]):
                raise ValueError("PID %d does not belong to an existing process" % pid_list[0])
        except ValueError:
            processes = dict((x.strip().split(None, 1) for x in subprocess.check_output(["pgrep", "-af", parameter]).split("\n") if x.strip()))
            if str(os.getpid()) in processes:
                del processes[str(os.getpid())]
            if not processes:
                raise ValueError("No process matches `%s'" % parameter)
            if len(processes) > 1:
                status(1, "exit", "Multiple choices: ")
                for pid, proc in processes.items():
                    print "       %05s %s" % (pid, proc)
                while True:
                    which = readline_timout("Which process do you want?", "all", 20, "^[0-9]+$")
                    if which == "all" or which in processes:
                        break
                if which != "all":
                    pid_list = [ int(which) ]
                else:
                    pid_list = map(int, processes.keys())
            else:
                pid_list = [ int(processes.keys()[0]) ]
            status(0, "exit", "Waiting for any of %d processes to exit" % len(pid_list))
        self.pid_list = pid_list

    def wait_for_event(self):
        while True:
            for pid in self.pid_list:
                if not OnPIDExit.is_alive(pid):
                    status(0, "exit", "PID %d exited" % pid, True)
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

        def __init__(self, parameter):
            self.ino = inotify.adapters.Inotify()
            files = glob.glob(parameter)
            for file_name in files:
                self.add_path(file_name)
            status(0, "inotify", "Watching %d files" % len(files))

        def add_path(self, path):
            self.ino.add_watch(path, inotify.constants.IN_CLOSE_WRITE | inotify.constants.IN_CREATE)
            if os.path.isdir(path):
                for elem in os.listdir(path):
                    sub_path = os.path.join(path, elem)
                    if os.path.isdir(sub_path):
                        self.add_path(sub_path)

        def wait_for_event(self):
            for event in self.ino.event_gen():
                if event is not None:
                    header, type_names, fdir, filename = event
                    path = os.path.join(fdir, filename)
                    status(0, "inotify", "%s updated" % path, True)
                    break
            return path
# }}}
# Network throughput {{{
class NetworkThroughput(OnEvent):
    DESCRIPTION = "Network throughput drops below a threshold"
    PREFIX = "nettput"
    PARAMETER_DESCRIPTION = "kiB/s"

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

    def __init__(self, parameter):
        self.threshold = float(parameter) * 1024
        self.nbytes = NetworkThroughput.get_bytes()
        self.time = time.time()
        time.sleep(1)
        status(0, "network", "Startup throughput is %2.2f kiB/s" % (self.get_throughput() / 1024, ))

    def wait_for_event(self):
        while True:
            time.sleep(10)
            throughput = self.get_throughput()
            status(0, "network", "Throughput is %2.2f kiB/s" % (throughput / 1024, ), True)
            if throughput < self.threshold:
                break
# }}}
# Ping {{{
class Pingable(OnEvent):
    DESCRIPTION = "Host replies to ping"
    PREFIX = "ping"
    PARAMETER_DESCRIPTION = "remote host"

    def __init__(self, parameter):
        self.parameter = parameter or "8.8.8.8"

    def wait_for_event(self):
        status(0, "ping", "Trying to ping %s" % self.parameter)
        with open("/dev/null", "w") as null:
            spinner = "|/-\\"
            n = 0
            while True:
                if subprocess.call(["ping", "-c", "1", "-W", "5", self.parameter], stdout=null, stderr=null) == 0:
                    status(0, "ping", "Received ping reply from %s" % self.parameter, True)
                    break
                else:
                    n += 1
                    status(0, "ping", "Didn't receive a ping reply from %s [%c]" % (self.parameter, spinner[n%len(spinner)]), True)
# }}}
# Socket connection {{{
class SocketConnection(OnEvent):
    DESCRIPTION = "Network connection to host is closed"
    PREFIX = "tcpconn"
    PARAMETER_DESCRIPTION = "remote host"

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

    def __init__(self, parameter):
        via = ""
        if re.match("^[0-9\.:]+$", parameter):
            self.ip = parameter
        else:
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
        status(0, "tcp", "Waiting for connection(s) to %s to be closed%s" % (self.ip, (" (found %s)" % via) if via else ""))

    def wait_for_event(self):
        while self.ip in (x[0] for x in SocketConnection.get_connections()):
            time.sleep(1)

# }}}
# CPU usage {{{
class CPUUsage(OnEvent):
    DESCRIPTION = "CPU usage drops below a threshold"
    PREFIX = "cpu"
    PARAMETER_DESCRIPTION = "percent"

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

    def __init__(self, parameter):
        self.threshold = float(parameter)
        self.stat = CPUUsage.get_stat()
        time.sleep(1)
        status(0, "cpu", "Startup CPU usage is %2.2f%%" % (self.get_usage(),))

    def wait_for_event(self):
        while True:
            time.sleep(1)
            try:
                usage = self.get_usage()
            except ZeroDivisionError:
                continue
            status(0, "cpu", "CPU usage is %2.2f%%" % (usage,), True)
            if usage < self.threshold:
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

        def __init__(self, parameter):
            with SupressOutput() as _:
                self.cam = cv2.VideoCapture(0)
            status(0, "movement", "Waiting for movement")

        def grab_frame(self):
            frame = self.cam.read()[1]
            while frame is None:
                with SupressOutput() as _:
                    self.cam = cv2.VideoCapture(0)
                frame = self.cam.read()[1]
            frame = cv2.cvtColor(frame, cv2.COLOR_RGB2GRAY)
            return frame
        def wait_for_event(self):
            while True:
                for i in range(10):
                    frame = self.grab_frame()
                maxVal = 0
                while maxVal < 60:
                    new_frame = self.grab_frame()
                    diff = cv2.absdiff(cv2.GaussianBlur(frame, (21, 21), 0), cv2.GaussianBlur(new_frame, (21, 21), 0))
                    frame = new_frame
                    (minVal, maxVal, minLoc, maxLoc) = cv2.minMaxLoc(diff)
                    status(0, "movement", "Movement level is %2d" % maxVal, True)
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

        def __init__(self, parameter):
            self.pcm = alsaaudio.PCM(alsaaudio.PCM_CAPTURE)
            self.pcm.setformat(alsaaudio.PCM_FORMAT_FLOAT_LE)
            self.pcm.setrate(16000)
            self.pcm.setchannels(1)
            status(0, "whistle", "Waiting for a whistle")

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
                        status(0, "whistle", "Center frequency %04.2f Hz is uninteresting" % f, True)
                    else:
                        time.sleep(.1)
                        f2, A2 = self.get_center_freq()
                        if abs(f - f2) > .5e3:
                            status(1, "whistle", "No whistle, %04.2f Hz fits but too short" % f, True)
                        else:
                            status(0, "whistle", "Got a whistle at %04.2f Hz with amplitude %03.2f" % (f, A), True)
                            return True
# }}}

def print_help():
    print "Execute a program once a certain event occurs"
    print "Syntax: on [-krw] [modifier(s)]<type>[:<arguments>] <action>"
    print
    print "Options:"
    print "  -k   Kill old action if it is retriggered too fast"
    print "  -r   Repeat action"
    print "  -w   Wait for action to complete before running it again"
    print "  -o   Neatly format the action's output"
    print
    print "Event types:"
    for cls in sorted(OnEvent.__subclasses__(), key=lambda x: x.PREFIX):
        print "  %-25s %s" % ("%s:<%s>" % (cls.PREFIX, cls.PARAMETER_DESCRIPTION) if cls.PARAMETER_DESCRIPTION else cls.PREFIX, cls.DESCRIPTION)
    print
    if Modifier.__subclasses__():
        print "Modifiers:"
        for cls in sorted(Modifier.__subclasses__(), key=lambda x: x.PREFIX):
            print "  %-25s %s" % (cls.PREFIX, cls.DESCRIPTION)

def status(level, component, line, is_update=False):
    if level == 0:
        col = "32"
    elif level == 1:
        col = "33"
    else:
        col = "31"
    up = "" if not is_update else "\033[1F\033[K"
    print "%s[\033[1;%sm%s\033[0m] %s" % (up, col, component, line)

def readline_timout(query, default, timeout=0, expect=None):
    class _TimeoutError(Exception):
        pass
    def _raise(*args):
        raise _TimeoutError()
    _old = signal.signal(signal.SIGALRM, _raise)
    try:
        while True:
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

class SupressOutput(object):
    def __enter__(self):
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

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "krwo")
        opts = dict(opts)
        event = args[0]
        parameter = None
        if ":" in event:
            event, parameter = event.split(":", 1)
        action = args[1:]
    except:
        print_help()
        sys.exit(1)

    modifiers = []
    if len(Modifier.__subclasses__()) > 0:
        while True:
            for cls in sorted(Modifier.__subclasses__(), key=lambda x: x.PREFIX):
                if event.startswith(cls.PREFIX):
                    modifiers.append(cls)
                    event = event[1:]
                    break
            else:
                continue
            break

    for cls in OnEvent.__subclasses__():
        if cls.PREFIX == event:
            handler = cls
            break
    else:
        print_help()
        print
        print "Unknown event type."
        sys.exit(1)

    ptarget = subprocess.PIPE if "-o" in opts else None
    proc = None
    while True:
        instance = handler(parameter)
        for modifier in modifiers:
            instance = modifier(instance, parameter)
        instance.wait_for_event()
        if "-k" in opts and proc:
            if proc.poll() is None:
                status(1, "on", "Killing old action instance %d" % proc.pid)
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.terminate()
                proc.wait()
        if action:
            if is_executable(action[0]):
                proc = subprocess.Popen(action, stdout=ptarget, stderr=ptarget, preexec_fn=os.setsid)
            else:
                proc = subprocess.Popen(action, shell=True, stdout=ptarget, stderr=ptarget, preexec_fn=os.setsid)
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

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
