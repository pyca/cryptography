# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography import x509


class TestBasicConstraints(object):
    def test_ca_not_boolean(self):
        with pytest.raises(TypeError):
            x509.BasicConstraints("notbool", None, False)

    def test_critical_not_boolean(self):
        with pytest.raises(TypeError):
            x509.BasicConstraints(False, None, "notbool")

    def test_path_length_not_ca(self):
        with pytest.raises(ValueError):
            x509.BasicConstraints(False, 0, True)

    def test_path_length_not_int(self):
        with pytest.raises(TypeError):
            x509.BasicConstraints(True, 1.1, True)

        with pytest.raises(TypeError):
            x509.BasicConstraints(True, "notint", True)

    def test_path_length_negative(self):
        with pytest.raises(TypeError):
            x509.BasicConstraints(True, -1, True)

    def test_repr(self):
        na = x509.BasicConstraints(True, None, True)
        assert repr(na) == (
            "<BasicConstraints(ca=True, path_length=None, critical=True)>"
        )
