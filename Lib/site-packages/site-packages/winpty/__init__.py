# -*- coding: utf-8 -*-
"""
Pywinpty
========
This package provides a Cython wrapper around winpty C++ library.
"""

# yapf: disable

# Local imports
from .ptyprocess import PtyProcess
from .winpty_wrapper import PTY


PTY
PtyProcess
VERSION_INFO = (0, 5, 7)
__version__ = '.'.join(map(str, VERSION_INFO))
