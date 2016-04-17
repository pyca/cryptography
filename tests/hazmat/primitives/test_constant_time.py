# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.hazmat.primitives import constant_time


class TestConstantTimeBytesEq(object):
    def test_reject_unicode(self):
        with pytest.raises(TypeError):
            constant_time.bytes_eq(b"foo", u"foo")

        with pytest.raises(TypeError):
            constant_time.bytes_eq(u"foo", b"foo")

        with pytest.raises(TypeError):
            constant_time.bytes_eq(u"foo", u"foo")

    def test_compares(self):
        assert constant_time.bytes_eq(b"foo", b"foo") is True

        assert constant_time.bytes_eq(b"foo", b"bar") is False

        assert constant_time.bytes_eq(b"foobar", b"foo") is False

        assert constant_time.bytes_eq(b"foo", b"foobar") is False
