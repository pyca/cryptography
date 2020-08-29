#!/usr/bin/env python
# encoding: utf-8

import Naked.settings
from Naked.toolshed.system import exit_success

class Version:
    def __init__(self):
        self.major_version = Naked.settings.major_version
        self.minor_version = Naked.settings.minor_version
        self.patch_version = Naked.settings.patch_version
        self.name = Naked.settings.app_name
        self.app_version_string = self.name + " " + self.major_version + "." + self.minor_version + "." + self.patch_version
        self.version_string = self.major_version + "." + self.minor_version + "." + self.patch_version

    def print_version(self):
        print(self.app_version_string)
        exit_success()

    def get_version(self):
        return self.version_string


if __name__ == '__main__':
    pass
