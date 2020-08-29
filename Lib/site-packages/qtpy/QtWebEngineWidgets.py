# -*- coding: utf-8 -*-
#
# Copyright © 2014-2015 Colin Duquesnoy
# Copyright © 2009- The Spyder development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)

"""
Provides QtWebEngineWidgets classes and functions.
"""

from . import PYQT5,PYSIDE2, PYQT4, PYSIDE, PythonQtError


# To test if we are using WebEngine or WebKit
WEBENGINE = True


if PYQT5:
    try:
        from PyQt5.QtWebEngineWidgets import QWebEnginePage
        from PyQt5.QtWebEngineWidgets import QWebEngineView
        from PyQt5.QtWebEngineWidgets import QWebEngineSettings
    except ImportError:
        from PyQt5.QtWebKitWidgets import QWebPage as QWebEnginePage
        from PyQt5.QtWebKitWidgets import QWebView as QWebEngineView
        from PyQt5.QtWebKit import QWebSettings as QWebEngineSettings
        WEBENGINE = False
elif PYSIDE2:
    from PySide2.QtWebEngineWidgets import QWebEnginePage
    from PySide2.QtWebEngineWidgets import QWebEngineView
    from PySide2.QtWebEngineWidgets import QWebEngineSettings
elif PYQT4:
    from PyQt4.QtWebKit import QWebPage as QWebEnginePage
    from PyQt4.QtWebKit import QWebView as QWebEngineView
    from PyQt4.QtWebKit import QWebSettings as QWebEngineSettings
    WEBENGINE = False
elif PYSIDE:
    from PySide.QtWebKit import QWebPage as QWebEnginePage
    from PySide.QtWebKit import QWebView as QWebEngineView
    from PySide.QtWebKit import QWebSettings as QWebEngineSettings
    WEBENGINE = False
else:
    raise PythonQtError('No Qt bindings could be found')
