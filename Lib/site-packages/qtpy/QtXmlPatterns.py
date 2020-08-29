# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Copyright © 2009- The Spyder Development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)
# -----------------------------------------------------------------------------
"""Provides QtXmlPatterns classes and functions."""

# Local imports
from . import PYQT4, PYSIDE2, PYQT5, PYSIDE, PythonQtError

if PYQT5:
    from PyQt5.QtXmlPatterns import *
elif PYSIDE2:
    from PySide2.QtXmlPatterns import *
elif PYQT4:
    from PyQt4.QtXmlPatterns import *
elif PYSIDE:
    from PySide.QtXmlPatterns import *
else:
    raise PythonQtError('No Qt bindings could be found')
