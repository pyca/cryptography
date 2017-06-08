# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography import utils


def test_deprecated_maccontext():
    with pytest.warns(utils.DeprecatedIn19):
        from cryptography.hazmat.primitives.interfaces import MACContext
        assert MACContext
