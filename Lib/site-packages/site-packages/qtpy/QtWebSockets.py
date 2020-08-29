# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Copyright © 2009- The Spyder Development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)
# -----------------------------------------------------------------------------
"""Provides QtWebSockets classes and functions."""

# Local imports
from . import PYSIDE2, PYQT5, PythonQtError

if PYQT5:
    from PyQt5.QtWebSockets import *
elif PYSIDE2:
    from PySide2.QtWebSockets import *
else:
    raise PythonQtError('No Qt bindings could be found')
