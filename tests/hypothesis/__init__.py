# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest
# hypothesis no longer supports Python 2.6 so we simply skip it there
pytest.importorskip("hypothesis")
