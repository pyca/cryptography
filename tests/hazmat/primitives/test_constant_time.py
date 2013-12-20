# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import pytest

import six

from cryptography.hazmat.primitives import constant_time


class TestConstantTimeBytesEq(object):
    def test_reject_unicode(self):
        with pytest.raises(TypeError):
            constant_time.bytes_eq(b"foo", six.u("foo"))

        with pytest.raises(TypeError):
            constant_time.bytes_eq(six.u("foo"), b"foo")

        with pytest.raises(TypeError):
            constant_time.bytes_eq(six.u("foo"), six.u("foo"))

    def test_compares(self):
        assert constant_time.bytes_eq(b"foo", b"foo") is True

        assert constant_time.bytes_eq(b"foo", b"bar") is False

        assert constant_time.bytes_eq(b"foobar", b"foo") is False

        assert constant_time.bytes_eq(b"foo", b"foobar") is False
