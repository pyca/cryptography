# -*- coding: utf-8 -*-

"""
clint.textui.validators
~~~~~~~~~~~~~~~~~~~~~~~

Core TextUI functionality for input validation.

"""

from __future__ import absolute_import

import os
import sys
import re

# Useful for very coarse version differentiation.
PY2 = sys.version_info[0] == 2
PY3 = sys.version_info[0] == 3

if PY3:
    string_types = str,
else:
    string_types = basestring,


class ValidationError(Exception):
    """An error while validating data."""

    def __init__(self, message):
        self.message = message
        self.error_list = [self]


class RegexValidator(object):
    regex = ''
    message = 'Enter a valid value.'

    def __init__(self, regex=None, message=None):
        if regex is not None:
            self.regex = regex
        if message is not None:
            self.message = message

        # Compile the regex if it was not passed pre-compiled.
        if isinstance(self.regex, string_types):
            self.regex = re.compile(self.regex)

    def __call__(self, value):
        """
        Validates that the input matches the regular expression.
        """
        if not self.regex.search(value):
            raise ValidationError(self.message)
        return value


class PathValidator(object):
    message = 'Enter a valid path.'

    def __init__(self, message=None):
        if message is not None:
            self.message = message

    def __call__(self, value):
        """
        Validates that the input is a valid directory.
        """
        if not os.path.isdir(value):
            raise ValidationError(self.message)
        return value


class FileValidator(object):
    message = 'Enter a valid file.'

    def __init__(self, message=None):
        if message is not None:
            self.message = message

    def __call__(self, value):
        """
        Validates that the input is a valid file.
        """
        if not os.path.isfile(value):
            raise ValidationError(self.message)
        return value


class IntegerValidator(object):
    message = 'Enter a valid number.'

    def __init__(self, message=None):
        if message is not None:
            self.message = message

    def __call__(self, value):
        """
        Validates that the input is a integer.
        """
        try:
            return int(value)
        except (TypeError, ValueError):
            raise ValidationError(self.message)

class OptionValidator(object):
    message = 'Select from the list of valid options.'

    def __init__(self, options, message=None):
        self.options = options
        if message is not None:
            self.message = message

    def __call__(self, value):
        """
        Validates that the input is in the options list.
        """
        if value in self.options:
            return value
        else:
            raise ValidationError(self.message)

