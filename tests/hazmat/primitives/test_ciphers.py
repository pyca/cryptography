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

import binascii

import pytest

from cryptography.hazmat.primitives.ciphers.algorithms import (
    AES, Camellia, TripleDES, Blowfish, CAST5
)


class TestAES(object):
    @pytest.mark.parametrize(("key", "keysize"), [
        (b"0" * 32, 128),
        (b"0" * 48, 192),
        (b"0" * 64, 256),
    ])
    def test_key_size(self, key, keysize):
        cipher = AES(binascii.unhexlify(key))
        assert cipher.key_size == keysize

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            AES(binascii.unhexlify(b"0" * 12))


class TestCamellia(object):
    @pytest.mark.parametrize(("key", "keysize"), [
        (b"0" * 32, 128),
        (b"0" * 48, 192),
        (b"0" * 64, 256),
    ])
    def test_key_size(self, key, keysize):
        cipher = Camellia(binascii.unhexlify(key))
        assert cipher.key_size == keysize

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            Camellia(binascii.unhexlify(b"0" * 12))


class TestTripleDES(object):
    @pytest.mark.parametrize("key", [
        b"0" * 16,
        b"0" * 32,
        b"0" * 48,
    ])
    def test_key_size(self, key):
        cipher = TripleDES(binascii.unhexlify(key))
        assert cipher.key_size == 192

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            TripleDES(binascii.unhexlify(b"0" * 12))


class TestBlowfish(object):
    @pytest.mark.parametrize(("key", "keysize"), [
        (b"0" * (keysize // 4), keysize) for keysize in range(32, 449, 8)
    ])
    def test_key_size(self, key, keysize):
        cipher = Blowfish(binascii.unhexlify(key))
        assert cipher.key_size == keysize

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            Blowfish(binascii.unhexlify(b"0" * 6))


class TestCAST5(object):
    @pytest.mark.parametrize(("key", "keysize"), [
        (b"0" * (keysize // 4), keysize) for keysize in range(40, 129, 8)
    ])
    def test_key_size(self, key, keysize):
        cipher = CAST5(binascii.unhexlify(key))
        assert cipher.key_size == keysize

    def test_invalid_key_size(self):
        with pytest.raises(ValueError):
            CAST5(binascii.unhexlify(b"0" * 34))
