# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from ..utils import WycheproofTest, skip_if_wycheproof_none


def test_wycheproof_test_repr():
    wycheproof = WycheproofTest({}, {"tcId": 3})
    assert repr(wycheproof) == "<WycheproofTest({}, {'tcId': 3}, tcId=3)>"


def test_skip_if_wycheproof_none():
    with pytest.raises(pytest.skip.Exception):
        skip_if_wycheproof_none(None)

    skip_if_wycheproof_none("abc")
