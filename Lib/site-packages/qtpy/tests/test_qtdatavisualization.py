from __future__ import absolute_import

import pytest
from qtpy import PYQT5, PYSIDE2

@pytest.mark.skipif(not (PYQT5 or PYSIDE2), reason="Only available in Qt5 bindings")
def test_qtdatavisualization():
    """Test the qtpy.QtDataVisualization namespace"""
    QtDataVisualization = pytest.importorskip("qtpy.QtDataVisualization")

    assert QtDataVisualization.QScatter3DSeries is not None
    assert QtDataVisualization.QSurfaceDataItem is not None
    assert QtDataVisualization.QSurface3DSeries is not None
    assert QtDataVisualization.QAbstract3DInputHandler is not None
    assert QtDataVisualization.QHeightMapSurfaceDataProxy is not None
    assert QtDataVisualization.QAbstractDataProxy is not None
    assert QtDataVisualization.Q3DCamera is not None
    assert QtDataVisualization.QAbstract3DGraph is not None
    assert QtDataVisualization.QCustom3DVolume is not None
    assert QtDataVisualization.Q3DInputHandler is not None
    assert QtDataVisualization.QBarDataProxy is not None
    assert QtDataVisualization.QSurfaceDataProxy is not None
    assert QtDataVisualization.QScatterDataItem is not None
    assert QtDataVisualization.Q3DLight is not None
    assert QtDataVisualization.QScatterDataProxy is not None
    assert QtDataVisualization.QValue3DAxis is not None
    assert QtDataVisualization.Q3DBars is not None
    assert QtDataVisualization.QBarDataItem is not None
    assert QtDataVisualization.QItemModelBarDataProxy is not None
    assert QtDataVisualization.Q3DTheme is not None
    assert QtDataVisualization.QCustom3DItem is not None
    assert QtDataVisualization.QItemModelScatterDataProxy is not None
    assert QtDataVisualization.QValue3DAxisFormatter is not None
    assert QtDataVisualization.QItemModelSurfaceDataProxy is not None
    assert QtDataVisualization.Q3DScatter is not None
    assert QtDataVisualization.QTouch3DInputHandler is not None
    assert QtDataVisualization.QBar3DSeries is not None
    assert QtDataVisualization.QAbstract3DAxis is not None
    assert QtDataVisualization.Q3DScene is not None
    assert QtDataVisualization.QCategory3DAxis is not None
    assert QtDataVisualization.QAbstract3DSeries is not None
    assert QtDataVisualization.Q3DObject is not None
    assert QtDataVisualization.QCustom3DLabel is not None
    assert QtDataVisualization.Q3DSurface is not None
    assert QtDataVisualization.QLogValue3DAxisFormatter is not None
    
