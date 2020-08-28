# -*- coding: utf-8 -*-
#
# Copyright © 2009- The Spyder Development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)

"""
Provides QtPrintSupport classes and functions.
"""

from . import PYQT5, PYQT4,PYSIDE2, PYSIDE, PythonQtError


if PYQT5:
    from PyQt5.QtPrintSupport import *
elif PYSIDE2:
    from PySide2.QtPrintSupport import *
elif PYQT4:
    from PyQt4.QtGui import (QAbstractPrintDialog, QPageSetupDialog,
                             QPrintDialog, QPrintEngine, QPrintPreviewDialog,
                             QPrintPreviewWidget, QPrinter, QPrinterInfo)
elif PYSIDE:
    from PySide.QtGui import (QAbstractPrintDialog, QPageSetupDialog,
                              QPrintDialog, QPrintEngine, QPrintPreviewDialog,
                              QPrintPreviewWidget, QPrinter, QPrinterInfo)
else:
    raise PythonQtError('No Qt bindings could be found')
