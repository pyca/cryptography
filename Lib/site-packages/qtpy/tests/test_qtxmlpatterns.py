from __future__ import absolute_import

import pytest
from qtpy import PYSIDE2, PYSIDE

def test_qtxmlpatterns():
    """Test the qtpy.QtXmlPatterns namespace"""
    from qtpy import QtXmlPatterns
    assert QtXmlPatterns.QAbstractMessageHandler is not None
    assert QtXmlPatterns.QAbstractUriResolver is not None
    assert QtXmlPatterns.QAbstractXmlNodeModel is not None
    assert QtXmlPatterns.QAbstractXmlReceiver is not None
    if not PYSIDE2 and not PYSIDE:
        assert QtXmlPatterns.QSimpleXmlNodeModel is not None
    assert QtXmlPatterns.QSourceLocation is not None
    assert QtXmlPatterns.QXmlFormatter is not None
    assert QtXmlPatterns.QXmlItem is not None
    assert QtXmlPatterns.QXmlName is not None
    assert QtXmlPatterns.QXmlNamePool is not None
    assert QtXmlPatterns.QXmlNodeModelIndex is not None
    assert QtXmlPatterns.QXmlQuery is not None
    assert QtXmlPatterns.QXmlResultItems is not None
    assert QtXmlPatterns.QXmlSchema is not None
    assert QtXmlPatterns.QXmlSchemaValidator is not None
    assert QtXmlPatterns.QXmlSerializer is not None
