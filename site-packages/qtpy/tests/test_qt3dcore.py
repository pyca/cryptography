from __future__ import absolute_import

import pytest
from qtpy import PYQT5, PYSIDE2

@pytest.mark.skipif(not (PYQT5 or PYSIDE2), reason="Only available in Qt5 bindings")
def test_qt3dcore():
    """Test the qtpy.Qt3DCore namespace"""
    Qt3DCore = pytest.importorskip("qtpy.Qt3DCore")

    assert Qt3DCore.QPropertyValueAddedChange is not None
    assert Qt3DCore.QSkeletonLoader is not None
    assert Qt3DCore.QPropertyNodeRemovedChange is not None
    assert Qt3DCore.QPropertyUpdatedChange is not None
    assert Qt3DCore.QAspectEngine is not None
    assert Qt3DCore.QPropertyValueAddedChangeBase is not None
    assert Qt3DCore.QStaticPropertyValueRemovedChangeBase is not None
    assert Qt3DCore.QPropertyNodeAddedChange is not None
    assert Qt3DCore.QDynamicPropertyUpdatedChange is not None
    assert Qt3DCore.QStaticPropertyUpdatedChangeBase is not None
    assert Qt3DCore.ChangeFlags is not None
    assert Qt3DCore.QAbstractAspect is not None
    assert Qt3DCore.QBackendNode is not None
    assert Qt3DCore.QTransform is not None
    assert Qt3DCore.QPropertyUpdatedChangeBase is not None
    assert Qt3DCore.QNodeId is not None
    assert Qt3DCore.QJoint is not None
    assert Qt3DCore.QSceneChange is not None
    assert Qt3DCore.QNodeIdTypePair is not None
    assert Qt3DCore.QAbstractSkeleton is not None
    assert Qt3DCore.QComponentRemovedChange is not None
    assert Qt3DCore.QComponent is not None
    assert Qt3DCore.QEntity is not None
    assert Qt3DCore.QNodeCommand is not None
    assert Qt3DCore.QNode is not None
    assert Qt3DCore.QPropertyValueRemovedChange is not None
    assert Qt3DCore.QPropertyValueRemovedChangeBase is not None
    assert Qt3DCore.QComponentAddedChange is not None
    assert Qt3DCore.QNodeCreatedChangeBase is not None
    assert Qt3DCore.QNodeDestroyedChange is not None
    assert Qt3DCore.QArmature is not None
    assert Qt3DCore.QStaticPropertyValueAddedChangeBase is not None
    assert Qt3DCore.ChangeFlag is not None
    assert Qt3DCore.QSkeleton is not None
