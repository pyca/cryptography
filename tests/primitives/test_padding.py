# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import absolute_import, division, print_function

import types

import pytest

from cryptography.primitives import padding


class TestPKCS7(object):

    @pytest.mark.parametrize("size", [127, 4096])
    def test_invalid_block_size(self, size):
        with pytest.raises(ValueError):
            padding.PKCS7(size)

    @pytest.mark.parametrize(("size", "padded"), [
        (128, b"1111"),
        (128, b"1111111111111111"),
        (128, b"111111111111111\x06"),
    ])
    def test_invalid_padding(self, size, padded):
        padder = padding.PKCS7(size)

        with pytest.raises(ValueError):
            padder.unpad(padded)

        with pytest.raises(ValueError):
            b"".join(padder.iter_unpad(padded))

    @pytest.mark.parametrize(("size", "unpadded", "padded"), [
        (
            128,
            b"1111111111",
            b"1111111111\x06\x06\x06\x06\x06\x06",
        ),
        (
            128,
            b"111111111111111122222222222222",
            b"111111111111111122222222222222\x02\x02",
        ),
        (
            128,
            iter(b"111111111111111122222222222222"),
            b"111111111111111122222222222222\x02\x02",
        ),
        (
            128,
            [b"1111", b"1111", b"1111", b"1111", b"2222", b"2222222222"],
            b"111111111111111122222222222222\x02\x02",
        ),
    ])
    def test_pad(self, size, unpadded, padded):
        padder = padding.PKCS7(size)
        assert padder.pad(unpadded) == padded

    @pytest.mark.parametrize(("size", "unpadded", "padded"), [
        (
            128,
            b"1111111111",
            b"1111111111\x06\x06\x06\x06\x06\x06",
        ),
        (
            128,
            b"111111111111111122222222222222",
            b"111111111111111122222222222222\x02\x02",
        ),
    ])
    def test_iter_pad(self, size, unpadded, padded):
        padder = padding.PKCS7(size)
        ipadded = padder.iter_pad(iter(unpadded))

        assert isinstance(ipadded, types.GeneratorType)
        assert b"".join(ipadded) == padded

    @pytest.mark.parametrize(("size", "unpadded", "padded"), [
        (
            128,
            b"1111111111",
            b"1111111111\x06\x06\x06\x06\x06\x06",
        ),
        (
            128,
            b"111111111111111122222222222222",
            b"111111111111111122222222222222\x02\x02",
        ),
        (
            128,
            b"111111111111111122222222222222",
            iter(b"111111111111111122222222222222\x02\x02"),
        ),
        (
            128,
            b"111111111111111122222222222222",
            [b"1111", b"1111", b"1111", b"1111", b"22222222222222\x02\x02"],
        ),
    ])
    def test_unpad(self, size, unpadded, padded):
        padder = padding.PKCS7(size)
        assert padder.unpad(padded) == unpadded

    @pytest.mark.parametrize(("size", "unpadded", "padded"), [
        (
            128,
            b"1111111111",
            b"1111111111\x06\x06\x06\x06\x06\x06",
        ),
        (
            128,
            b"111111111111111122222222222222",
            b"111111111111111122222222222222\x02\x02",
        ),
    ])
    def test_iter_unpad(self, size, unpadded, padded):
        padder = padding.PKCS7(size)
        iunpadded = padder.iter_unpad(iter(padded))

        assert isinstance(iunpadded, types.GeneratorType)
        assert b"".join(iunpadded) == unpadded
