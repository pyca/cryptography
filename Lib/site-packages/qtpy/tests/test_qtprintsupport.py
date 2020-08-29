from __future__ import absolute_import

import pytest
from qtpy import QtPrintSupport


def test_qtprintsupport():
    """Test the qtpy.QtPrintSupport namespace"""
    assert QtPrintSupport.QAbstractPrintDialog is not None
    assert QtPrintSupport.QPageSetupDialog is not None
    assert QtPrintSupport.QPrintDialog is not None
    assert QtPrintSupport.QPrintPreviewDialog is not None
    assert QtPrintSupport.QPrintEngine is not None
    assert QtPrintSupport.QPrinter is not None
    assert QtPrintSupport.QPrinterInfo is not None
    assert QtPrintSupport.QPrintPreviewWidget is not None
	

