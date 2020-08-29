from __future__ import absolute_import

import pytest
from qtpy import PYQT5, PYSIDE2

@pytest.mark.skipif(not (PYQT5 or PYSIDE2), reason="Only available in Qt5 bindings")
def test_qtwebchannel():
    """Test the qtpy.QtWebChannel namespace"""
    from qtpy import QtWebChannel

    assert QtWebChannel.QWebChannel is not None
    assert QtWebChannel.QWebChannelAbstractTransport is not None

