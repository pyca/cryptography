#!/usr/bin/env python
# encoding: utf-8

from Naked.toolshed.system import exit_success
#------------------------------------------------------------------------------
# [ compile_c_code function ] (--none--)
#  compile C files in the lib/Naked/toolshed/c directory
#------------------------------------------------------------------------------
def compile_c_code(abs_dirpath):
    from Naked.toolshed.shell import execute
    from os import chdir

    chdir(abs_dirpath)
    print('•naked• Compiling the C source library files...')
    success = execute("python setup.py build_ext --inplace")
    if success:
        print(' ')
        print('•naked• C source code compile complete.')
        exit_success()

def help():
    help_string = """
Naked build Command Help
========================
The build command compiles the Naked C libraries.  This requires an installed C compiler.

USAGE
  naked build

SECONDARY COMMANDS
  none

OPTIONS
  none"""
    print(help_string)
    exit_success()


if __name__ == '__main__':
    pass
