from __future__ import absolute_import

import os
import sys

import pytest
from qtpy import PYSIDE2, QtGui, QtWidgets


PY3 = sys.version[0] == "3"


def get_qapp(icon_path=None):
    qapp = QtWidgets.QApplication.instance()
    if qapp is None:
        qapp = QtWidgets.QApplication([''])
    return qapp


class Data(object):
    """
    Test class to store in userData. The __getitem__ is needed in order to
    reproduce the segmentation fault.
    """
    def __getitem__(self, item):
        raise ValueError("Failing")


@pytest.mark.skipif(PY3 or (PYSIDE2 and os.environ.get('CI', None) is not None),
                    reason="It segfaults in Python 3 and in our CIs with PySide2")
def test_patched_qcombobox():
    """
    In PySide, using Python objects as userData in QComboBox causes
    Segmentation faults under certain conditions. Even in cases where it
    doesn't, findData does not work correctly. Likewise, findData also
    does not work correctly with Python objects when using PyQt4. On the
    other hand, PyQt5 deals with this case correctly. We therefore patch
    QComboBox when using PyQt4 and PySide to avoid issues.
    """

    app = get_qapp()

    data1 = Data()
    data2 = Data()
    data3 = Data()
    data4 = Data()
    data5 = Data()
    data6 = Data()

    icon1 = QtGui.QIcon()
    icon2 = QtGui.QIcon()

    widget = QtWidgets.QComboBox()
    widget.addItem('a', data1)
    widget.insertItem(0, 'b', data2)
    widget.addItem('c', data1)
    widget.setItemData(2, data3)
    widget.addItem(icon1, 'd', data4)
    widget.insertItem(3, icon2, 'e', data5)
    widget.addItem(icon1, 'f')
    widget.insertItem(5, icon2, 'g')

    widget.show()

    assert widget.findData(data1) == 1
    assert widget.findData(data2) == 0
    assert widget.findData(data3) == 2
    assert widget.findData(data4) == 4
    assert widget.findData(data5) == 3
    assert widget.findData(data6) == -1

    assert widget.itemData(0) == data2
    assert widget.itemData(1) == data1
    assert widget.itemData(2) == data3
    assert widget.itemData(3) == data5
    assert widget.itemData(4) == data4
    assert widget.itemData(5) is None
    assert widget.itemData(6) is None

    assert widget.itemText(0) == 'b'
    assert widget.itemText(1) == 'a'
    assert widget.itemText(2) == 'c'
    assert widget.itemText(3) == 'e'
    assert widget.itemText(4) == 'd'
    assert widget.itemText(5) == 'g'
    assert widget.itemText(6) == 'f'


@pytest.mark.skipif((PYSIDE2 and os.environ.get('CI', None) is not None),
                    reason="It segfaults in our CIs with PYSIDE2")
def test_model_item():
    """
    This is a regression test for an issue that caused the call to item(0)
    below to trigger segmentation faults in PySide. The issue is
    non-deterministic when running the call once, so we include a loop to make
    sure that we trigger the fault.
    """
    app = get_qapp()
    combo = QtWidgets.QComboBox()
    label_data = [('a', None)]
    for iter in range(10000):
        combo.clear()
        for i, (label, data) in enumerate(label_data):
            combo.addItem(label, userData=data)
        model = combo.model()
        model.item(0)
