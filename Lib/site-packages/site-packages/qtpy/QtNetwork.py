# -*- coding: utf-8 -*-
#
# Copyright © 2014-2015 Colin Duquesnoy
# Copyright © 2009- The Spyder Development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)

"""
Provides QtNetwork classes and functions.
"""

from . import PYQT5, PYSIDE2, PYQT4, PYSIDE, PythonQtError


if PYQT5:
    from PyQt5.QtNetwork import *
elif PYSIDE2:
    from PySide2.QtNetwork import *
elif PYQT4:
    from PyQt4.QtNetwork import *
elif PYSIDE:
    from PySide.QtNetwork import *
else:
    raise PythonQtError('No Qt bindings could be found')
