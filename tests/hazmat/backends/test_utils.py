# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.hazmat.backends.utils import _SizeValidator


class TestSizeValidator(object):
    def test_update(self):
        validator = _SizeValidator(1024, "test")
        assert validator.update(b"1234") is None
        assert validator._len == 4
        assert validator.update(b"1234") is None
        assert validator._len == (4 + 4)

    def test_update_invalid(self):
        validator = _SizeValidator(1024, "test")
        assert validator.update(b"0" * 1024) is None
        assert validator.validate() is None
        with pytest.raises(ValueError) as e:
            validator.update(b"1")
            validator.validate()
        assert "test" in "%s" % e.value

    def test_validate(self):
        validator = _SizeValidator(1024, "test")
        assert validator.validate() is None
        validator._len = 1023
        assert validator.validate() is None
        validator._len = 1024
        assert validator.validate() is None

    def test_validate_invalid(self):
        validator = _SizeValidator(1024, "test")
        validator._len = 1025
        with pytest.raises(ValueError):
            validator.validate()

    def test_validate_large_num(self):
        validator = _SizeValidator((2 ** 64) / 8, "test")
        validator._len = validator._max_bytes
        with pytest.raises(ValueError):
            validator.update_and_validate(b"0")
