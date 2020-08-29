# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Copyright © 2019- The Spyder Development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)
# -----------------------------------------------------------------------------
"""Provides QtChart classes and functions."""

# Local imports
from . import PYQT5, PYSIDE2, PythonQtError

if PYQT5:
    try:
        from PyQt5 import QtChart as QtCharts
    except ImportError:
        raise PythonQtError('The QtChart module was not found. '
                            'It needs to be installed separately for PyQt5.')
elif PYSIDE2:
    from PySide2.QtCharts import *
else:
    raise PythonQtError('No Qt bindings could be found')
