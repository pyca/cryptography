# Licensed under the GPL: https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
# For details: https://github.com/PyCQA/pylint/blob/master/COPYING

#!/usr/bin/env python
import os
import sys

import pylint

# Strip out the current working directory from sys.path.
# Having the working directory in `sys.path` means that `pylint` might
# inadvertently import user code from modules having the same name as
# stdlib or pylint's own modules.
# CPython issue: https://bugs.python.org/issue33053
if sys.path[0] == "" or sys.path[0] == os.getcwd():
    sys.path.pop(0)

pylint.run_pylint()
