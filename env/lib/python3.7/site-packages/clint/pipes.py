# -*- coding: utf-8 -*-

"""
clint.pipes
~~~~~~~~~~~

This module contains the helper functions for dealing with unix pipes.

"""

from __future__ import absolute_import
from __future__ import with_statement

import sys


__all__ = ('piped_in', )



def piped_in():
    """Returns piped input via stdin, else None."""
    with sys.stdin as stdin:
        # TTY is only way to detect if stdin contains data
        if not stdin.isatty():
            return stdin.read()  
        else:
            return None
