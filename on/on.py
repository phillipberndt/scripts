#!/usr/bin/env python
# encoding: utf-8
import getopt
import glob
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import time

class OnEvent(object):
    DESCRIPTION = "sample description"
    PREFIX = "sample"
    PARAMETER_DESCRIPTION = None

    def __init__(self, parameter):
        pass

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
            processes = dict((x.strip().split(None, 1) for x in subprocess.check_output(["pgrep", "-lf", parameter]).split("\n") if x.strip()))
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
    import pyinotify
    has_pyinotify = True
except:
    has_pyinotify = False

if has_pyinotify:
    class OnFileChange(OnEvent):
        DESCRIPTION = "Wait for a file or directory to change"
        PREFIX = "inotify"
        PARAMETER_DESCRIPTION = "file"

        def __init__(self, parameter):
            self.wm = pyinotify.WatchManager()
            files = glob.glob(parameter)
            for file_name in files:
                self.wm.add_watch(file_name, pyinotify.IN_CLOSE_WRITE, rec=True)
            status(0, "inotify", "Watching %d files" % len(files))

        def wait_for_event(self):
            notifier = pyinotify.Notifier(self.wm)
            notifier.process_events()
            notifier.check_events()
            notifier.read_events()
            path = notifier._sys_proc_fun(notifier._eventq[0]).pathname
            status(0, "inotify", "%s updated" % path, True)
            return path
# }}}
# Network throughput {{{
class NetworkThroughput(OnEvent):
    DESCRIPTION = "Network throughput drops below a threshold"
    PREFIX = "network"
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
# Socket connection {{{
class SocketConnection(OnEvent):
    DESCRIPTION = "Network connection to host is closed"
    PREFIX = "tcp"
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
                ips = socket.gethostbyaddr("xx" + parameter)[2]
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
    print "Syntax: on [-krw] <type>[:<arguments>] <action>"
    print
    print "Options:"
    print "  -k   Kill old action if it is retriggered too fast"
    print "  -r   Repeat action"
    print "  -w   Wait for action to complete before running it again"
    print
    print "Event types:"
    for cls in sorted(OnEvent.__subclasses__(), key=lambda x: x.PREFIX):
        print "  %-20s %s" % ("%s:<%s>" % (cls.PREFIX, cls.PARAMETER_DESCRIPTION) if cls.PARAMETER_DESCRIPTION else cls.PREFIX, cls.DESCRIPTION)

def status(level, component, line, is_update=False):
    if level == 0:
        col = "32"
    elif level == 1:
        col = "33"
    else:
        col = "31"
    up = "" if not is_update else "\033[1F\033[K"
    print "%s[\033[%sm%s\033[0m] %s" % (up, col, component, line)

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

def main():
    try:
        opts, args = getopt.getopt(sys.argv[1:], "krw")
        opts = dict(opts)
        event = args[0]
        parameter = None
        if ":" in event:
            event, parameter = event.split(":", 1)
        action = args[1:]
    except:
        print_help()
        sys.exit(1)

    for cls in OnEvent.__subclasses__():
        if cls.PREFIX == event:
            handler = cls
            break
    else:
        print_help()
        print
        print "Unknown event type."
        sys.exit(1)

    proc = None
    while True:
        instance = handler(parameter)
        instance.wait_for_event()
        if "-k" in opts and proc:
            if proc.poll() is None:
                status(1, "on", "Killing old action instance %d" % proc.pid)
                proc.kill()
        if action:
            if is_executable(action[0]):
                proc = subprocess.Popen(action)
            else:
                proc = subprocess.Popen(action, shell=True)
            if "-w" in opts:
                proc.wait()
        if "-r" not in opts:
            break

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
