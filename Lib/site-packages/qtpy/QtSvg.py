# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Copyright © 2009- The Spyder Development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)
# -----------------------------------------------------------------------------
"""Provides QtSvg classes and functions."""

# Local imports
from . import PYQT4, PYSIDE2, PYQT5, PYSIDE, PythonQtError

if PYQT5:
    from PyQt5.QtSvg import *
elif PYSIDE2:
    from PySide2.QtSvg import *
elif PYQT4:
    from PyQt4.QtSvg import *
elif PYSIDE:
    from PySide.QtSvg import *
else:
    raise PythonQtError('No Qt bindings could be found')

del PYQT4, PYQT5, PYSIDE, PYSIDE2
