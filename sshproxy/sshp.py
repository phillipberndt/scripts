#!/usr/bin/env python
# encoding: utf-8
from __future__ import print_function
import os
import sys

SSH_PARAMETERS_WITHOUT_ARGUMENTS = "1246AaCfgKkMNnqsTtVvXxYy"

def shell_quote(s):
    if " " in s or "'" in s or ";" in s or "\"" in s:
        return "'" + s.replace("'", "'\\''") + "'"
    return s

def split_ssh_calls(args):
    options = []
    levels  = []
    port    = 22

    while args:
        arg = args.pop(0)
        if arg == "--":
            break
        elif arg[0] == "-":
            arg = list(arg)
            arg.pop(0)
            while arg:
                char = arg.pop(0)
                options.append("-%c" % char)
                if char not in SSH_PARAMETERS_WITHOUT_ARGUMENTS:
                    if arg:
                        options.append("".join(arg))
                        break
                    else:
                        options.append(args.pop(0))
                        break
                    if char == "p":
                        port = int(options.pop())
        else:
            host = arg
            if ":" in host:
                host, port = host.split(":")
                port = int(port)
            levels.append((host, port, options))
            options = []
            port = 22

    return levels, args

def build_ssh_command_line(levels, args):
    command_line = ""
    while len(levels) > 1:
        host, port, options = levels.pop(0)
        if command_line:
            command_line = " ".join([ "ssh", "-o", shell_quote("ProxyCommand=%s" % command_line.replace('%', '%%')) ] + list(map(shell_quote, options)) + [ "-W", "%h:%p", shell_quote(host) ])
        else:
            command_line = " ".join([ "ssh", "-p", str(port) ] + list(map(shell_quote, options)) + [ "-W", "%h:%p", shell_quote(host) ])

    host, port, options = levels.pop(0)
    if command_line:
        return [ "ssh", "-o", "ProxyCommand=%s" % command_line ] + options + [ host ] + args
    else:
        return [ "ssh", "-p", str(port) ] + options + [ host ] + args


if __name__ == "__main__":
    debug = False
    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        sys.argv.pop(1)
        debug = True

    if len(sys.argv) == 1:
        print("sshp -- SSH proxy command line builder")
        print("Syntax: ssp [-d] [options for hop1] [user@]hop1[:port] [options for hop2] [user@]hop2[:port] ... [options for final host] [user@]host[:port] [-- program to run]")
        print()
        print("Use option -d to print the SSH command instead of running it.")
        print()
        sys.exit(0)

    levels, args = split_ssh_calls(sys.argv[1:])
    command = build_ssh_command_line(levels, args)
    if debug:
        print(" ".join(map(shell_quote, command)))
    else:
        os.execvp("ssh", command)
