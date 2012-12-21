#!/usr/bin/env python
# encoding: utf-8

import os
from setuptools import setup

def read(fname):
	return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
	name = "venv",
	version = "0.0.1",
	author = "Phillip Berndt",
	author_email = "phillip.berndt@googlemail.com",
	description = ("A tool to easily setup sandboxed environments, but not only for python"),
	license = "GPL",
	keywords = "venv sandbox",
	url = "https://github.com/phillipberndt/venv",
	packages = [ 'venv' ],
	entry_points = {
		"console_scripts": [
			"venv = venv.venv:main"
		]
	},
	long_description = read('README'),
	classifiers=[
		"Development Status :: 3 - Alpha",
		"Topic :: Utilities",
		"License :: OSI Approved :: GNU General Public License (GPL)",
	],
)
