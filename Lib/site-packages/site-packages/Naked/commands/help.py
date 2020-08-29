#!/usr/bin/env python
# encoding: utf-8

import Naked.settings
from Naked.toolshed.system import exit_success

class Help:
    def __init__(self):
        self.help = Naked.settings.help

    def print_help(self):
        print(self.help)
        exit_success()


if __name__ == '__main__':
    pass
