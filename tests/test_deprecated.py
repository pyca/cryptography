# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from tests import deprecated


def test_deprecated_name():
    def deprecated_func():
        return deprecated.old_name

    assert pytest.deprecated_call(deprecated_func) == 1


def test_deprecated_from_import():
    def deprecated_func():
        from tests.deprecated import old_name
        return old_name

    assert pytest.deprecated_call(deprecated_func) == 1


def test_not_deprecated():
    def deprecated_func():
        return deprecated.new_name

    assert deprecated_func() == 2
