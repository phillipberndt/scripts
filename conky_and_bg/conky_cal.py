#!/usr/bin/env python
# encoding: utf-8
import pexpect
import os

os.environ["TERM"] = "xterm-color"

cal = pexpect.spawn("cal")
out = cal.read()

print "   " + out.replace("\n", "\n   ").replace("\x1b[7m", "${color FF0000}").replace("\x1b[m", "${color 000000}")
