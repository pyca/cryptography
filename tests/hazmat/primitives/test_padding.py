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

import pytest

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
    ])
    def test_invalid_padding(self, size, padded):
        padder = padding.PKCS7(size)

        unpadder = padder.unpadder()
        with pytest.raises(ValueError):
            unpadder.update(padded)
            unpadder.finalize()

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
        padder = padding.PKCS7(size)
        padder = padder.padder()
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
        padder = padding.PKCS7(size)
        unpadder = padder.unpadder()
        result = unpadder.update(padded)
        result += unpadder.finalize()
        assert result == unpadded

    def test_use_after_finalize(self):
        p = padding.PKCS7(128)

        padder = p.padder()
        b = padder.finalize()
        with pytest.raises(ValueError):
            padder.update(b"")
        with pytest.raises(ValueError):
            padder.finalize()

        unpadder = p.unpadder()
        unpadder.update(b)
        unpadder.finalize()
        with pytest.raises(ValueError):
            unpadder.update(b"")
        with pytest.raises(ValueError):
            unpadder.finalize()
