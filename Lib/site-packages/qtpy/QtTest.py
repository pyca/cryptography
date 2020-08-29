# -*- coding: utf-8 -*-
#
# Copyright © 2014-2015 Colin Duquesnoy
# Copyright © 2009- The Spyder Developmet Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)

"""
Provides QtTest and functions
"""

from . import PYQT5,PYSIDE2, PYQT4, PYSIDE, PythonQtError


if PYQT5:
    from PyQt5.QtTest import QTest
elif PYSIDE2:
    from PySide2.QtTest import QTest
elif PYQT4:
    from PyQt4.QtTest import QTest as OldQTest

    class QTest(OldQTest):
        @staticmethod
        def qWaitForWindowActive(QWidget):
            OldQTest.qWaitForWindowShown(QWidget)
elif PYSIDE:
    from PySide.QtTest import QTest
else:
    raise PythonQtError('No Qt bindings could be found')
