# venv ########################################################################
A tool to setup virtual environments for more than just python

Copyright (c) 2011, Phillip Berndt

Feel free to reuse and redistribute this program under the terms of the GNU
Public Licence, which you can find here: http://www.gnu.org/copyleft/gpl.html

## Why and what ###############################################################
I found that I often need this and that it is complicated to get all the
neccessary tools, so I decided to write this script. It's in its very early
stages, so don't expect everything to run fluently yet.

This script currently supports:

 * virtualenv (Python)
 * sandbox (the one from Gentoo, like FreeBSD's jail but not as secure)
 * wineprefix
 * setting `$HOME` to the sandbox'es main directory
 * installation of the tools above

Please send me suggestions, improvements, etc.!

## Installation ###############################################################
If you like setuptools, run `./setup.py install`. If you don't, use the
`pipless_setup.sh` script. All it does is copying `./venv/venv.py` to
`$YOUR_DESIRED_LOCATION/bin/venv`
