# The code below, as well as the associated test were adapted from
# qt-helpers, which was released under a 3-Clause BSD license:
#
# Copyright (c) 2015, Chris Beaumont and Thomas Robitaille
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of the Glue project nor the names of its
#    contributors may be used to endorse or promote products derived
#    from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
# IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


def patch_qcombobox(QComboBox):
    """
    In PySide, using Python objects as userData in QComboBox causes
    Segmentation faults under certain conditions. Even in cases where it
    doesn't, findData does not work correctly. Likewise, findData also does not
    work correctly with Python objects when using PyQt4. On the other hand,
    PyQt5 deals with this case correctly. We therefore patch QComboBox when
    using PyQt4 and PySide to avoid issues.
    """

    from ..QtGui import QIcon
    from ..QtCore import Qt, QObject

    class userDataWrapper():
        """
        This class is used to wrap any userData object. If we don't do this,
        then certain types of objects can cause segmentation faults or issues
        depending on whether/how __getitem__ is defined.
        """
        def __init__(self, data):
            self.data = data

    _addItem = QComboBox.addItem

    def addItem(self, *args, **kwargs):
        if len(args) == 3 or (not isinstance(args[0], QIcon)
                              and len(args) == 2):
            args, kwargs['userData'] = args[:-1], args[-1]
        if 'userData' in kwargs:
            kwargs['userData'] = userDataWrapper(kwargs['userData'])
        _addItem(self, *args, **kwargs)

    _insertItem = QComboBox.insertItem

    def insertItem(self, *args, **kwargs):
        if len(args) == 4 or (not isinstance(args[1], QIcon)
                              and len(args) == 3):
            args, kwargs['userData'] = args[:-1], args[-1]
        if 'userData' in kwargs:
            kwargs['userData'] = userDataWrapper(kwargs['userData'])
        _insertItem(self, *args, **kwargs)

    _setItemData = QComboBox.setItemData

    def setItemData(self, index, value, role=Qt.UserRole):
        value = userDataWrapper(value)
        _setItemData(self, index, value, role=role)

    _itemData = QComboBox.itemData

    def itemData(self, index, role=Qt.UserRole):
        userData = _itemData(self, index, role=role)
        if isinstance(userData, userDataWrapper):
            userData = userData.data
        return userData

    def findData(self, value):
        for i in range(self.count()):
            if self.itemData(i) == value:
                return i
        return -1

    QComboBox.addItem = addItem
    QComboBox.insertItem = insertItem
    QComboBox.setItemData = setItemData
    QComboBox.itemData = itemData
    QComboBox.findData = findData