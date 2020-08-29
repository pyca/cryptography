#!/usr/bin/env python
# encoding: utf-8
# tests: test_PYTHON.py

from sys import version_info

#------------------------------------------------------------------------------
# Python Versions
#------------------------------------------------------------------------------

#------------------------------------------------------------------------------
# [ py_version function ] (tuple of (major, minor, patch))
#------------------------------------------------------------------------------
def py_version():
	return (version_info[0], version_info[1], version_info[2])

#------------------------------------------------------------------------------
# [ py_major_version function ] (integer)
#   Return Python interpreter major version number
#------------------------------------------------------------------------------
def py_major_version():
	return (version_info[0])

#------------------------------------------------------------------------------
# [ py_minor_version function ] (integer)
#  Return Python interpreter minor version number
#------------------------------------------------------------------------------
def py_minor_version():
	return (version_info[1])

#------------------------------------------------------------------------------
# [ py_patch_version function ] (integer)
#  Return Python interpreter patch version number
#------------------------------------------------------------------------------
def py_patch_version():
	return (version_info[2])

#------------------------------------------------------------------------------
# [ is_py2 function ] (boolean)
#   Return truth result for question is interpreter running a version of Python 2
#------------------------------------------------------------------------------
def is_py2():
	return (version_info[0] == (2))

#------------------------------------------------------------------------------
# [ is_py3 function ] (boolean)
#  Return truth result for question is interpreter running a version of Python 3
#------------------------------------------------------------------------------
def is_py3():
	return (version_info[0] == (3))

if __name__ == '__main__':
	pass
