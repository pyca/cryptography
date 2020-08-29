# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Copyright © 2009- The Spyder Development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)
# -----------------------------------------------------------------------------
"""Provides QtQml classes and functions."""

# Local imports
from . import PYQT5, PYSIDE2, PythonQtError

if PYQT5:
    from PyQt5.QtQml import *
elif PYSIDE2:
    from PySide2.QtQml import *
else:
    raise PythonQtError('No Qt bindings could be found')
