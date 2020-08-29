"""Test QDesktopServices split in Qt5."""

from __future__ import absolute_import

import pytest
import warnings
from qtpy import PYQT4, PYSIDE


def test_qstandarpath():
    """Test the qtpy.QStandardPaths namespace"""
    from qtpy.QtCore import QStandardPaths

    assert QStandardPaths.StandardLocation is not None

    # Attributes from QDesktopServices shouldn't be in QStandardPaths
    with pytest.raises(AttributeError) as excinfo:
        QStandardPaths.setUrlHandler


def test_qdesktopservice():
    """Test the qtpy.QDesktopServices namespace"""
    from qtpy.QtGui import QDesktopServices

    assert QDesktopServices.setUrlHandler is not None


@pytest.mark.skipif(not (PYQT4 or PYSIDE), reason="Warning is only raised in old bindings")
def test_qdesktopservice_qt4_pyside():
    from qtpy.QtGui import QDesktopServices
    # Attributes from QStandardPaths should raise a warning when imported
    # from QDesktopServices
    with warnings.catch_warnings(record=True) as w:
        # Cause all warnings to always be triggered.
        warnings.simplefilter("always")
        # Try to  import QtHelp.
        QDesktopServices.StandardLocation

        assert len(w) == 1
        assert issubclass(w[-1].category, DeprecationWarning)
        assert "deprecated" in str(w[-1].message)
