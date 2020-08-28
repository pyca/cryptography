#!/usr/bin/env python
# encoding: utf-8

import os
from Naked.toolshed.system import file_exists, dir_exists, stderr, exit_success

class Profiler:
    def __init__(self, dir_levels = 6):
        self.number_of_dir_levels = dir_levels # number of directory levels to bottom to top search

    def run(self):
        lib_found = False
        for i in range(self.number_of_dir_levels):
            if not self._is_lib_at_this_level():
                os.chdir(os.pardir)
            else:
                lib_found = True
                break
        if lib_found:
            os.chdir('lib') # chdir to the lib directory if it is found
            if file_exists('profiler.py'): # confirm that profiler.py exists
                os.system('python profiler.py') # run the profiler.py file
                exit_success()
            else:
                stderr("Unable to locate a profiler.py file in your lib directory.", 1)
        else:
            stderr("Unable to locate your profiler.py file.  Please navigate to your project directory.", 1)

    def _is_lib_at_this_level(self):
        if dir_exists('lib'):
            return True
        else:
            return False


def help():
    from Naked.toolshed.system import exit_success
    help_string = """
Naked profile Command Help
==========================
The profile command runs cProfile and pstats on the code that you enter in test code block of your PROJECT/lib/profiler.py file.

USAGE
  naked profile

SECONDARY COMMANDS
  none

OPTIONS
  none

This command searches bottom to top (from the working directory) through up to 6 directory levels to identify the lib/profiler.py path."""

    print(help_string)
    exit_success()

