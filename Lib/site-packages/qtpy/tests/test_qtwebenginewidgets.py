from __future__ import absolute_import

import pytest
from qtpy import QtWebEngineWidgets


def test_qtwebenginewidgets():
    """Test the qtpy.QtWebSockets namespace"""

    assert QtWebEngineWidgets.QWebEnginePage is not None
    assert QtWebEngineWidgets.QWebEngineView is not None
    assert QtWebEngineWidgets.QWebEngineSettings is not None
