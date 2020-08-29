#!/usr/bin/env python
# encoding: utf-8
# cython: profile=False

from Naked.settings import debug as DEBUG_FLAG
from Naked.toolshed.c.system import cwd
import Naked.toolshed.c.python as py
import sys
import os
import datetime

class StateObject:
	def __init__(self):
		now = datetime.datetime.now()
		self.py2 = py.is_py2() #truth test Python 2 interpreter
		self.py3 = py.is_py3() #truth test Python 3 interpreter
		self.py_major = py.py_major_version() #Python major version
		self.py_minor = py.py_minor_version() #Python minor version
		self.py_patch = py.py_patch_version() #Python patch version
		self.os = sys.platform #user operating system
		self.cwd = cwd() #current (present) working directory
		self.parent_dir = os.pardir
		self.default_path = os.defpath
		self.user_path = os.path.expanduser("~")
		self.string_encoding = sys.getdefaultencoding()
		self.file_encoding = sys.getfilesystemencoding()
		self.hour = now.hour
		self.min = now.minute
		self.year = now.year
		self.day = now.day
		self.month = now.month
		self.second = now.second

if __name__ == '__main__':
	pass
