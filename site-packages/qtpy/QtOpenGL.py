# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Copyright © 2009- The Spyder Development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)
# -----------------------------------------------------------------------------
"""Provides QtOpenGL classes and functions."""

# Local imports
from . import PYQT4, PYQT5, PYSIDE, PYSIDE2, PythonQtError

if PYQT5:
    from PyQt5.QtOpenGL import *
elif PYSIDE2:
    from PySide2.QtOpenGL import *
elif PYQT4:
    from PyQt4.QtOpenGL import *
elif PYSIDE:
    from PySide.QtOpenGL import *
else:
    raise PythonQtError('No Qt bindings could be found')

del PYQT4, PYQT5, PYSIDE, PYSIDE2
