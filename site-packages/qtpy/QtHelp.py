# -*- coding: utf-8 -*-
#
# Copyright © 2009- The Spyder Development Team
#
# Licensed under the terms of the MIT License
# (see LICENSE.txt for details)

"""QtHelp Wrapper."""

import warnings

from . import PYQT5
from . import PYQT4
from . import PYSIDE
from . import PYSIDE2

if PYQT5:
    from PyQt5.QtHelp import *
elif PYSIDE2:
    from PySide2.QtHelp import *
elif PYQT4:
    from PyQt4.QtHelp import *
elif PYSIDE:
    from PySide.QtHelp import *
