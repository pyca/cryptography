# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Copyright © 2009- The Spyder Development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)
# -----------------------------------------------------------------------------
"""Provides QtSql classes and functions."""

# Local imports
from . import PYQT5, PYSIDE2, PYQT4, PYSIDE, PythonQtError

if PYQT5:
    from PyQt5.QtSql import *
elif PYSIDE2:
    from PySide2.QtSql import *
elif PYQT4:
    from PyQt4.QtSql import *
elif PYSIDE:
    from PySide.QtSql import *
else:
    raise PythonQtError('No Qt bindings could be found')

del PYQT4, PYQT5, PYSIDE, PYSIDE2
