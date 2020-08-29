from __future__ import absolute_import

import pytest


def test_qtsvg():
    """Test the qtpy.QtSvg namespace"""
    from qtpy import QtSvg

    assert QtSvg.QGraphicsSvgItem is not None
    assert QtSvg.QSvgGenerator is not None
    assert QtSvg.QSvgRenderer is not None
    assert QtSvg.QSvgWidget is not None
