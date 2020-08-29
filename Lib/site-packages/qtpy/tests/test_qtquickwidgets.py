from __future__ import absolute_import

import pytest
from qtpy import PYQT5, PYSIDE2

@pytest.mark.skipif(not (PYQT5 or PYSIDE2), reason="Only available in Qt5 bindings")
def test_qtquickwidgets():
    """Test the qtpy.QtQuickWidgets namespace"""
    from qtpy import QtQuickWidgets
    assert QtQuickWidgets.QQuickWidget is not None
