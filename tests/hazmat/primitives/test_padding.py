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

import pytest

import six

from cryptography.exceptions import AlreadyFinalized
from cryptography.hazmat.primitives import padding


class TestPKCS7(object):
    @pytest.mark.parametrize("size", [127, 4096, -2])
    def test_invalid_block_size(self, size):
        with pytest.raises(ValueError):
            padding.PKCS7(size)

    @pytest.mark.parametrize(("size", "padded"), [
        (128, b"1111"),
        (128, b"1111111111111111"),
        (128, b"111111111111111\x06"),
        (128, b""),
        (128, b"\x06" * 6),
        (128, b"\x00" * 16),
    ])
    def test_invalid_padding(self, size, padded):
        unpadder = padding.PKCS7(size).unpadder()
        with pytest.raises(ValueError):
            unpadder.update(padded)
            unpadder.finalize()

    def test_non_bytes(self):
        padder = padding.PKCS7(128).padder()
        with pytest.raises(TypeError):
            padder.update(six.u("abc"))
        unpadder = padding.PKCS7(128).unpadder()
        with pytest.raises(TypeError):
            unpadder.update(six.u("abc"))

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
            b"1" * 16,
            b"1" * 16 + b"\x10" * 16,
        ),
        (
            128,
            b"1" * 17,
            b"1" * 17 + b"\x0F" * 15,
        )
    ])
    def test_pad(self, size, unpadded, padded):
        padder = padding.PKCS7(size).padder()
        result = padder.update(unpadded)
        result += padder.finalize()
        assert result == padded

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
    def test_unpad(self, size, unpadded, padded):
        unpadder = padding.PKCS7(size).unpadder()
        result = unpadder.update(padded)
        result += unpadder.finalize()
        assert result == unpadded

    def test_use_after_finalize(self):
        padder = padding.PKCS7(128).padder()
        b = padder.finalize()
        with pytest.raises(AlreadyFinalized):
            padder.update(b"")
        with pytest.raises(AlreadyFinalized):
            padder.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        unpadder.update(b)
        unpadder.finalize()
        with pytest.raises(AlreadyFinalized):
            unpadder.update(b"")
        with pytest.raises(AlreadyFinalized):
            unpadder.finalize()
