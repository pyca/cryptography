# -*- coding: utf-8 -*-
# -----------------------------------------------------------------------------
# Copyright © 2009- The Spyder Development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)
# -----------------------------------------------------------------------------
"""Provides QtDataVisualization classes and functions."""

# Local imports
from . import PYQT5, PYSIDE2, PythonQtError

if PYQT5:
    from PyQt5.QtDataVisualization import *
elif PYSIDE2:
    # https://bugreports.qt.io/projects/PYSIDE/issues/PYSIDE-1026
    import PySide2.QtDataVisualization as __temp
    import inspect
    for __name in inspect.getmembers(__temp.QtDataVisualization):
        globals()[__name[0]] = __name[1]
else:
    raise PythonQtError('No Qt bindings could be found')
