#!/usr/bin/env python
# encoding: utf-8

import Naked.settings
from Naked.toolshed.system import exit_success

class Usage:
    def __init__(self):
        self.usage = Naked.settings.usage

    def print_usage(self):
        print(self.usage)
        exit_success()


if __name__ == '__main__':
    pass
