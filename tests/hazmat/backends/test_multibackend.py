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

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.interfaces import (
    CipherBackend, HashBackend, HMACBackend, PBKDF2HMACBackend
)
from cryptography.hazmat.backends.multibackend import PrioritizedMultiBackend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


@utils.register_interface(CipherBackend)
class DummyCipherBackend(object):
    def __init__(self, supported_ciphers):
        self._ciphers = supported_ciphers

    def cipher_supported(self, algorithm, mode):
        return (type(algorithm), type(mode)) in self._ciphers

    def create_symmetric_encryption_ctx(self, algorithm, mode):
        if not self.cipher_supported(algorithm, mode):
            raise UnsupportedAlgorithm

    def create_symmetric_decryption_ctx(self, algorithm, mode):
        if not self.cipher_supported(algorithm, mode):
            raise UnsupportedAlgorithm


@utils.register_interface(HashBackend)
class DummyHashBackend(object):
    def __init__(self, supported_algorithms):
        self._algorithms = supported_algorithms

    def hash_supported(self, algorithm):
        return type(algorithm) in self._algorithms

    def create_hash_ctx(self, algorithm):
        if not self.hash_supported(algorithm):
            raise UnsupportedAlgorithm


@utils.register_interface(HMACBackend)
class DummyHMACBackend(object):
    def __init__(self, supported_algorithms):
        self._algorithms = supported_algorithms

    def hmac_supported(self, algorithm):
        return type(algorithm) in self._algorithms

    def create_hmac_ctx(self, key, algorithm):
        if not self.hmac_supported(algorithm):
            raise UnsupportedAlgorithm


@utils.register_interface(PBKDF2HMACBackend)
class DummyPBKDF2HMAC(object):
    def __init__(self, supported_algorithms):
        self._algorithms = supported_algorithms

    def pbkdf2_hmac_supported(self, algorithm):
        return type(algorithm) in self._algorithms

    def derive_pbkdf2_hmac(self, algorithm, length, salt, iterations,
                           key_material):
        if not self.pbkdf2_hmac_supported(algorithm):
            raise UnsupportedAlgorithm



class TestPrioritizedMultiBackend(object):
    def test_ciphers(self):
        backend = PrioritizedMultiBackend([
            DummyHashBackend([]),
            DummyCipherBackend([
                (algorithms.AES, modes.CBC),
            ])
        ])
        assert backend.cipher_supported(
            algorithms.AES(b"\x00" * 16), modes.CBC(b"\x00" * 16)
        )

        cipher = Cipher(
            algorithms.AES(b"\x00" * 16),
            modes.CBC(b"\x00" * 16),
            backend=backend
        )
        cipher.encryptor()
        cipher.decryptor()

        cipher = Cipher(
            algorithms.Camellia(b"\x00" * 16),
            modes.CBC(b"\x00" * 16),
            backend=backend
        )
        with pytest.raises(UnsupportedAlgorithm):
            cipher.encryptor()
        with pytest.raises(UnsupportedAlgorithm):
            cipher.decryptor()

    def test_hashes(self):
        backend = PrioritizedMultiBackend([
            DummyHashBackend([hashes.MD5])
        ])
        assert backend.hash_supported(hashes.MD5())

        hashes.Hash(hashes.MD5(), backend=backend)

        with pytest.raises(UnsupportedAlgorithm):
            hashes.Hash(hashes.SHA1(), backend=backend)

    def test_hmac(self):
        backend = PrioritizedMultiBackend([
            DummyHMACBackend([hashes.MD5])
        ])
        assert backend.hmac_supported(hashes.MD5())

        hmac.HMAC(b"", hashes.MD5(), backend=backend)

        with pytest.raises(UnsupportedAlgorithm):
            hmac.HMAC(b"", hashes.SHA1(), backend=backend)

    def test_pbkdf2(self):
        backend = PrioritizedMultiBackend([
            DummyPBKDF2HMAC([hashes.MD5])
        ])
        assert backend.pbkdf2_hmac_supported(hashes.MD5())

        backend.derive_pbkdf2_hmac(hashes.MD5(), 10, b"", 10, b"")

        with pytest.raises(UnsupportedAlgorithm):
            backend.derive_pbkdf2_hmac(hashes.SHA1(), 10, b"", 10, b"")
