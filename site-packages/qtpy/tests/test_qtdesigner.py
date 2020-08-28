from __future__ import absolute_import

import pytest
from qtpy import PYSIDE2, PYSIDE

@pytest.mark.skipif(PYSIDE2 or PYSIDE, reason="QtDesigner is not avalaible in PySide/PySide2")
def test_qtdesigner():
    from qtpy import QtDesigner
    """Test the qtpy.QtDesigner namespace"""
    assert QtDesigner.QAbstractExtensionFactory is not None
    assert QtDesigner.QAbstractExtensionManager is not None
    assert QtDesigner.QDesignerActionEditorInterface is not None
    assert QtDesigner.QDesignerContainerExtension is not None
    assert QtDesigner.QDesignerCustomWidgetCollectionInterface is not None
    assert QtDesigner.QDesignerCustomWidgetInterface is not None
    assert QtDesigner.QDesignerFormEditorInterface is not None
    assert QtDesigner.QDesignerFormWindowCursorInterface is not None
    assert QtDesigner.QDesignerFormWindowInterface is not None
    assert QtDesigner.QDesignerFormWindowManagerInterface is not None
    assert QtDesigner.QDesignerMemberSheetExtension is not None
    assert QtDesigner.QDesignerObjectInspectorInterface is not None
    assert QtDesigner.QDesignerPropertyEditorInterface is not None
    assert QtDesigner.QDesignerPropertySheetExtension is not None
    assert QtDesigner.QDesignerTaskMenuExtension is not None
    assert QtDesigner.QDesignerWidgetBoxInterface is not None
    assert QtDesigner.QExtensionFactory is not None
    assert QtDesigner.QExtensionManager is not None
    assert QtDesigner.QFormBuilder is not None