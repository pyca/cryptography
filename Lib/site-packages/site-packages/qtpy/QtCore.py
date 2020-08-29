# -*- coding: utf-8 -*-
#
# Copyright © 2014-2015 Colin Duquesnoy
# Copyright © 2009- The Spyder Development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)

"""
Provides QtCore classes and functions.
"""

from . import PYQT5, PYSIDE2, PYQT4, PYSIDE, PythonQtError


if PYQT5:
    from PyQt5.QtCore import *
    from PyQt5.QtCore import pyqtSignal as Signal
    from PyQt5.QtCore import pyqtSlot as Slot
    from PyQt5.QtCore import pyqtProperty as Property
    from PyQt5.QtCore import QT_VERSION_STR as __version__

    # For issue #153
    from PyQt5.QtCore import QDateTime
    QDateTime.toPython = QDateTime.toPyDateTime

    # Those are imported from `import *`
    del pyqtSignal, pyqtSlot, pyqtProperty, QT_VERSION_STR
elif PYSIDE2:
    from PySide2.QtCore import *

    try:  # may be limited to PySide-5.11a1 only 
        from PySide2.QtGui import QStringListModel
    except:
        pass

    import PySide2.QtCore
    __version__ = PySide2.QtCore.__version__
elif PYQT4:
    from PyQt4.QtCore import *
    # Those are things we inherited from Spyder that fix crazy crashes under
    # some specific situations. (See #34)
    from PyQt4.QtCore import QCoreApplication
    from PyQt4.QtCore import Qt
    from PyQt4.QtCore import pyqtSignal as Signal
    from PyQt4.QtCore import pyqtSlot as Slot
    from PyQt4.QtCore import pyqtProperty as Property
    from PyQt4.QtGui import (QItemSelection, QItemSelectionModel,
                             QItemSelectionRange, QSortFilterProxyModel,
                             QStringListModel)
    from PyQt4.QtCore import QT_VERSION_STR as __version__
    from PyQt4.QtCore import qInstallMsgHandler as qInstallMessageHandler

    # QDesktopServices has has been split into (QDesktopServices and
    # QStandardPaths) in Qt5
    # This creates a dummy class that emulates QStandardPaths
    from PyQt4.QtGui import QDesktopServices as _QDesktopServices

    class QStandardPaths():
        StandardLocation = _QDesktopServices.StandardLocation
        displayName = _QDesktopServices.displayName
        DesktopLocation = _QDesktopServices.DesktopLocation
        DocumentsLocation = _QDesktopServices.DocumentsLocation
        FontsLocation = _QDesktopServices.FontsLocation
        ApplicationsLocation = _QDesktopServices.ApplicationsLocation
        MusicLocation = _QDesktopServices.MusicLocation
        MoviesLocation = _QDesktopServices.MoviesLocation
        PicturesLocation = _QDesktopServices.PicturesLocation
        TempLocation = _QDesktopServices.TempLocation
        HomeLocation = _QDesktopServices.HomeLocation
        DataLocation = _QDesktopServices.DataLocation
        CacheLocation = _QDesktopServices.CacheLocation
        writableLocation = _QDesktopServices.storageLocation

    # Those are imported from `import *`
    del pyqtSignal, pyqtSlot, pyqtProperty, QT_VERSION_STR, qInstallMsgHandler
elif PYSIDE:
    from PySide.QtCore import *
    from PySide.QtGui import (QItemSelection, QItemSelectionModel,
                              QItemSelectionRange, QSortFilterProxyModel,
                              QStringListModel)
    from PySide.QtCore import qInstallMsgHandler as qInstallMessageHandler
    del qInstallMsgHandler

    # QDesktopServices has has been split into (QDesktopServices and
    # QStandardPaths) in Qt5
    # This creates a dummy class that emulates QStandardPaths
    from PySide.QtGui import QDesktopServices as _QDesktopServices

    class QStandardPaths():
        StandardLocation = _QDesktopServices.StandardLocation
        displayName = _QDesktopServices.displayName
        DesktopLocation = _QDesktopServices.DesktopLocation
        DocumentsLocation = _QDesktopServices.DocumentsLocation
        FontsLocation = _QDesktopServices.FontsLocation
        ApplicationsLocation = _QDesktopServices.ApplicationsLocation
        MusicLocation = _QDesktopServices.MusicLocation
        MoviesLocation = _QDesktopServices.MoviesLocation
        PicturesLocation = _QDesktopServices.PicturesLocation
        TempLocation = _QDesktopServices.TempLocation
        HomeLocation = _QDesktopServices.HomeLocation
        DataLocation = _QDesktopServices.DataLocation
        CacheLocation = _QDesktopServices.CacheLocation
        writableLocation = _QDesktopServices.storageLocation

    import PySide.QtCore
    __version__ = PySide.QtCore.__version__
else:
    raise PythonQtError('No Qt bindings could be found')
