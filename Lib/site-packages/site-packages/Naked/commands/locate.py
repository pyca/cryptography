#!/usr/bin/env python
# encoding: utf-8

import os
from Naked.toolshed.system import stderr, exit_success

class Locator:
    def __init__(self, needle):
        self.needle = needle
        self.location = self._display_location()

    def _display_location(self):
        if self.needle == 'main':
            main_path = os.path.join('<PROJECT>', 'lib', '<PROJECT>', 'app.py')
            print("app.py : " + main_path)
            exit_success()
        elif self.needle == "settings":
            settings_path = os.path.join('<PROJECT>', 'lib', '<PROJECT>','settings.py')
            print("settings.py : " + settings_path)
            exit_success()
        elif self.needle == "setup":
            setup_path = os.path.join('<PROJECT>', 'setup.py')
            print("setup.py : " + setup_path)
            exit_success()
        else:
            stderr("Unable to process the command.  Use 'naked locate help' for more information.", 1)

def help():
    help_string = """
Naked locate Command Help
=========================
The locate command identifies the file path to commonly used files in your project directory.

USAGE
  naked locate <argument>

SECONDARY COMMANDS
  main     -  the main application script file, app.py
  setup    -  the setup.py file
  settings -  the project settings files, settings.py

OPTIONS
  none

EXAMPLE
  naked locate main"""
    print(help_string)
    exit_success()

if __name__ == '__main__':
    pass
