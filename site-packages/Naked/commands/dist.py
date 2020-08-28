#!/usr/bin/env python
# encoding: utf-8

import os
from Naked.toolshed.system import file_exists, stderr, exit_success
from Naked.toolshed.shell import run as shell_run

class Dist:
    def __init__(self):
        self.register = "python setup.py register"
        self.sdist = "python setup.py sdist upload"
        self.wheel = "python setup.py bdist_wheel upload"
        self.swheel = "python setup.py sdist bdist_wheel upload"
        self.win = "python setup.py bdist_wininst upload"
        self.all = "python setup.py sdist bdist_wheel bdist_wininst upload"

    #------------------------------------------------------------------------------
    # [ run method ] - iterates through up to 6 directories above current working
    #                  directory and then runs command if setup.py found
    #------------------------------------------------------------------------------
    def run(self, command):
        setuppy_found = False
        for i in range(6): # navigate up at most 4 directory levels to search for the setup.py file
            if not self._is_setup_py_at_this_level():
                os.chdir(os.pardir)
            else:
                setuppy_found = True
                self._run_dist_command(command)
                break
        if not setuppy_found:
            stderr("Unable to locate the setup.py file for your project.  Please confirm that you are in your project directory and try again.", 1)
        else:
            exit_success()

    # search for setup.py file
    def _is_setup_py_at_this_level(self):
        if file_exists('setup.py'):
            return True
        else:
            return False

    # run the user requested command
    def _run_dist_command(self, the_command):
        if the_command in "register":
            print('•naked• Running register...')
            shell_run(self.register)
        elif the_command in "sdist":
            print('•naked• Running sdist...')
            shell_run(self.sdist)
        elif the_command in "wheel":
            print('•naked• Running wheel...')
            shell_run(self.wheel)
        elif the_command in "swheel":
            print('•naked• Running swheel...')
            shell_run(self.swheel)
        elif the_command in "win":
            print('•naked• Running win...')
            shell_run(self.win)
        elif the_command in "all":
            print('•naked• Running all...')
            shell_run(self.all)
        else:
            stderr("Unrecognized command.  Use 'naked dist help' to view the supported commands.", 1)


def help():
    help_string = """
Naked dist Command Help
=======================
The dist secondary commands run the standard distutils 'python setup.py <command>' source/binary distribution commands.

USAGE
  naked dist <secondary_command>

SECONDARY COMMANDS   python setup.py <command(s)>
  all                  sdist bdist_wheel bdist_wininst upload
  register             register
  sdist                sdist upload
  swheel               sdist bdist_wheel upload
  wheel                bdist_wheel upload
  win                  bdist_wininst upload

OPTIONS
  none

EXAMPLES
  naked dist register
  naked dist sdist"""
    print(help_string)
    exit_success()

if __name__ == '__main__':
    pass
