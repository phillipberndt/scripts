#!/usr/bin/env python
# encoding: utf-8
import getopt
import glob
import os
import re
import subprocess
import sys
import time

class OnEvent(object):
    DESCRIPTION = "sample description"
    PREFIX = "sample"
    PARAMETER_DESCRIPTION = "file"

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
            processes = map(int, subprocess.check_output(["pgrep", "-f", parameter]).split())
            if os.getpid() in processes:
                processes.remove(os.getpid())
            if not processes:
                raise ValueError("No process matches `%s'" % parameter)
            if len(processes) > 1:
                print "Warning: `%s' matches %d processes." % (parameter, len(processes))
            pid_list = processes
        self.pid_list = pid_list

    def wait_for_event(self):
        while True:
            for pid in self.pid_list:
                if not OnPIDExit.is_alive(pid):
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
            for file_name in glob.glob(parameter):
                self.wm.add_watch(file_name, pyinotify.IN_CLOSE_WRITE, rec=True)

        def wait_for_event(self):
            notifier = pyinotify.Notifier(self.wm)
            notifier.process_events()
            notifier.check_events()
            notifier.read_events()
            return notifier._sys_proc_fun(notifier._eventq[0]).pathname
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
        print "Info: Startup throughput is %2.2f kiB/s" % (self.get_throughput() / 1024)

    def wait_for_event(self):
        while True:
            time.sleep(10)
            throughput = self.get_throughput()
            if throughput < self.threshold:
                break
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
    for cls in OnEvent.__subclasses__():
        print "  %-20s %s" % ("%s:<%s>" % (cls.PREFIX, cls.PARAMETER_DESCRIPTION) if cls.PARAMETER_DESCRIPTION else cls.PREFIX, cls.DESCRIPTION)

def is_executable(file_name):
    for path in os.environ["PATH"].split(":"):
        if os.access(os.path.join(path, file_name), os.X_OK | os.F_OK):
            return True
    return False

if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "krw")
        opts = dict(opts)
        event = args[0]
        parameter = ""
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
                print "Info: Killing old action instance %d" % proc.pid
                proc.kill()
        if is_executable(action[0]):
            proc = subprocess.Popen(action)
        else:
            proc = subprocess.Popen(action, shell=True)
        if "-w" in opts:
            proc.wait()
        if "-r" not in opts:
            break
