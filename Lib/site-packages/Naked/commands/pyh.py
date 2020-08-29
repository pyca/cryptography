#!/usr/bin/env python
# encoding: utf-8

import sys

def python_help(help_string):
    try:
        needle = help_string
        if needle.startswith("'") and needle.endswith("'"):
            needle = needle[1:-1]
        elif needle.startswith('"') and needle.endswith('"'):
            needle = needle[1:-1]
        help(needle)
    except Exception as e:
        print(e)
        sys.stderr.write("•naked• There was an error processing the query.")
        sys.exit(1)

def pyh_help():
    from Naked.toolshed.system import exit_success
    help_string = """
Naked pyh Command Help
======================
The pyh command searches the built-in Python documentation for a query term.  The query term can be a Python built-in module, class/type, method, or function.

USAGE
  naked pyh <query>

SECONDARY COMMANDS
  none

OPTIONS
  none

EXAMPLES
  Module Docs:   naked pyh sys

  Class Docs:    naked pyh dict

  Method Docs:   naked pyh dict.update

  Function Docs: naked pyh max"""

    print(help_string)
    exit_success()

if __name__ == '__main__':
    pass
