# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

import pytest

from cryptography import utils


class TestCachedProperty(object):
    def test_simple(self):
        class T(object):
            @utils.cached_property
            def t(self):
                accesses.append(None)
                return 14

        accesses: typing.List[typing.Optional[T]] = []

        assert T.t
        t = T()
        assert t.t == 14
        assert len(accesses) == 1
        assert t.t == 14
        assert len(accesses) == 1

        t = T()
        assert t.t == 14
        assert len(accesses) == 2
        assert t.t == 14
        assert len(accesses) == 2

    def test_set(self):
        class T(object):
            @utils.cached_property
            def t(self):
                accesses.append(None)
                return 14

        accesses: typing.List[typing.Optional[T]] = []
        t = T()
        with pytest.raises(AttributeError):
            t.t = None
        assert len(accesses) == 0
        assert t.t == 14
        assert len(accesses) == 1
        with pytest.raises(AttributeError):
            t.t = None
        assert len(accesses) == 1
        assert t.t == 14
        assert len(accesses) == 1
