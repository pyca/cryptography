from __future__ import absolute_import

import pytest
from qtpy import PYSIDE2


@pytest.mark.skipif(not PYSIDE2, reason="Only available by default in PySide2")
def test_qtcharts():
    """Test the qtpy.QtCharts namespace"""
    from qtpy import QtCharts
    assert QtCharts.QtCharts.QChart is not None
