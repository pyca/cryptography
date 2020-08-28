from __future__ import absolute_import

import pytest
from qtpy import PYQT5, PYSIDE2

@pytest.mark.skipif(not (PYQT5 or PYSIDE2), reason="Only available in Qt5 bindings")
def test_qt3dlogic():
    """Test the qtpy.Qt3DLogic namespace"""
    Qt3DLogic = pytest.importorskip("qtpy.Qt3DLogic")
  
    assert Qt3DLogic.QLogicAspect is not None
    assert Qt3DLogic.QFrameAction is not None
