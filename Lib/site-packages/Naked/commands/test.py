#!/usr/bin/env python
# encoding: utf-8

import os
from Naked.toolshed.system import cwd, file_exists, dir_exists, stderr, exit_success

#------------------------------------------------------------------------------
# [ ToxTester class ]
#  Run Tox on the project directory, by default runs all python versions in tox.ini
#  Optional specify the version of Python to test in constructor (runs 'tox -e py<version>')
#  Optional specify the number of directory levels `dir_levels` to search bottom to top (default = 4)
#------------------------------------------------------------------------------
class ToxTester:
    def __init__(self, py_version="", dir_levels = 6):
        self.py_version = py_version
        self.number_of_dir_levels = dir_levels

    def run(self):
        tox_found = False
        for i in range(self.number_of_dir_levels):
            if not self._is_tox_ini_at_this_level():
                os.chdir(os.pardir)
            else:
                tox_found = True
                self._run_tox()
                break
        if not tox_found:
            stderr("Unable to locate your tox.ini file.  Please navigate to your project directory.", 1)
        else:
            exit_success()

    def _is_tox_ini_at_this_level(self):
        if file_exists('tox.ini'):
            return True
        else:
            return False

    def _run_tox(self):
        if self.py_version == "":
            os.system("tox")
        else:
            cmd_string = "tox -e" + self.py_version
            os.system(cmd_string)

#------------------------------------------------------------------------------
# [ NoseTester class ]
#   run nose tests from the tests directory (works from any level of the project)
#   Optional specify the number of directory levels to search bottom to top (default = 4)
#------------------------------------------------------------------------------
class NoseTester:
    def __init__(self, dir_levels = 6):
        self.number_of_dir_levels = dir_levels

    def run(self):
        nose_found = False
        for i in range(self.number_of_dir_levels):
            if not self._is_testdir_at_this_level():
                os.chdir(os.pardir)
            else:
                nose_found = True
                self._run_nose()
                break
        if not nose_found:
            stderr("Unable to locate your testing directory", 1)
        else:
            exit_success()

    def _is_testdir_at_this_level(self):
        if file_exists('setup.py'):
            if dir_exists('tests'):
                return True
            else:
                return False #found setup.py but no tests directory
        else:
            return False # setup.py not at this level

    def _run_nose(self):
        os.system("nosetests --where=tests")


#------------------------------------------------------------------------------
# [ PyTester class ]
#  run py.test test runner in the tests directory
#  Optional specify the number of directory levels to search bottom to top (default = 4)
#------------------------------------------------------------------------------
class PyTester:
    def __init__(self, dir_levels = 6):
        self.number_of_dir_levels = dir_levels

    def run(self):
        py_found = False
        for i in range(self.number_of_dir_levels):
            if not self._is_testdir_at_this_level():
                os.chdir(os.pardir)
            else:
                py_found = True
                self._run_pytests()
                break
        if not py_found:
            stderr("Unable to locate your testing directory", 1)
        else:
            exit_success()

    def _is_testdir_at_this_level(self):
        if file_exists('setup.py'):
            if dir_exists('tests'):
                return True
            else:
                return False
        else:
            return False

    def _run_pytests(self):
        os.chdir('tests')
        os.system('py.test')

#------------------------------------------------------------------------------
# [ UnitTester class ]
#  run Python unit tests with the built in unittest methods
#  Optional specify the number of directory levels to search bottom to top (default = 4)
#------------------------------------------------------------------------------
class UnitTester:
    def __init__(self, the_unit_test, dir_levels = 6):
        self.unittest = the_unit_test
        self.number_of_dir_levels = dir_levels

    def run(self):
        unit_found = False
        for i in range(self.number_of_dir_levels):
            if not self._is_testdir_at_this_level():
                os.chdir(os.pardir)
            else:
                unit_found = True
                os.chdir('tests')
                if file_exists(self.unittest):
                    self._run_unittest()
                else:
                    stderr("The unit test file " + self.unittest + " could not be found in the tests directory.")
        if not unit_found:
            stderr("Unable to locate your testing directory", 1)
        else:
            exit_success()

    def _is_testdir_at_this_level(self):
        if file_exists('setup.py'):
            if dir_exists('tests'):
                return True
            else:
                return False
        else:
            return False

    def _run_unittest(self):
        cmd_string = "python " + self.unittest
        os.system(cmd_string)


def help():
    help_string = """
Naked test Command Help
=======================
The test command allows you to run unit tests from any working directory in your project.

USAGE
  naked test <secondary command> [argument]

SECONDARY COMMANDS
  nose      -  run the nose test runner on your project
  pytest    -  run the py.test test runner on your project
  tox       -  run the tox test runner on your project
  unittest  -  run Python unit tests (built-in)

ARGUMENTS
  nose
     -- does not take additional arguments

  pytest
     -- does not take additional arguments

  tox [python version]
     -- You can include an optional tox Python version argument to run your
        tests with a single version of Python (instead of the versions
        specified in the tox.ini file). By default, the versions specified
        in your tox.ini file are run.

  unittest <test file>
     -- Mandatory unit test file path (relative to the tests directory)

OPTIONS
  none

EXAMPLES
  naked test nose
  naked test pytest
  naked test tox
  naked test tox py27
  naked test unittest test_app.py

A bottom to top search (from the working directory) is performed over up to 6 directory levels to find the 'tests' directory."""
    print(help_string)
    exit_success()

if __name__ == '__main__':
    pass
