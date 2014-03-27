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

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.interfaces import (
    CipherBackend, HMACBackend, HashBackend, PBKDF2HMACBackend, RSABackend
)


@utils.register_interface(CipherBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
@utils.register_interface(PBKDF2HMACBackend)
@utils.register_interface(RSABackend)
class MultiBackend(object):
    name = "multibackend"

    def __init__(self, backends):
        self._backends = backends

    def _filtered_backends(self, interface):
        for b in self._backends:
            if isinstance(b, interface):
                yield b

    def cipher_supported(self, algorithm, mode):
        return any(
            b.cipher_supported(algorithm, mode)
            for b in self._filtered_backends(CipherBackend)
        )

    def create_symmetric_encryption_ctx(self, algorithm, mode):
        for b in self._filtered_backends(CipherBackend):
            try:
                return b.create_symmetric_encryption_ctx(algorithm, mode)
            except UnsupportedAlgorithm:
                pass
        raise UnsupportedAlgorithm(
            "None of the constituents backends support this algorithm."
        )

    def create_symmetric_decryption_ctx(self, algorithm, mode):
        for b in self._filtered_backends(CipherBackend):
            try:
                return b.create_symmetric_decryption_ctx(algorithm, mode)
            except UnsupportedAlgorithm:
                pass
        raise UnsupportedAlgorithm(
            "None of the constituents backends support this algorithm."
        )

    def hash_supported(self, algorithm):
        return any(
            b.hash_supported(algorithm)
            for b in self._filtered_backends(HashBackend)
        )

    def create_hash_ctx(self, algorithm):
        for b in self._filtered_backends(HashBackend):
            try:
                return b.create_hash_ctx(algorithm)
            except UnsupportedAlgorithm:
                pass
        raise UnsupportedAlgorithm(
            "None of the constituents backends support this algorithm."
        )

    def hmac_supported(self, algorithm):
        return any(
            b.hmac_supported(algorithm)
            for b in self._filtered_backends(HMACBackend)
        )

    def create_hmac_ctx(self, key, algorithm):
        for b in self._filtered_backends(HMACBackend):
            try:
                return b.create_hmac_ctx(key, algorithm)
            except UnsupportedAlgorithm:
                pass
        raise UnsupportedAlgorithm(
            "None of the constituents backends support this algorithm."
        )

    def pbkdf2_hmac_supported(self, algorithm):
        return any(
            b.pbkdf2_hmac_supported(algorithm)
            for b in self._filtered_backends(PBKDF2HMACBackend)
        )

    def derive_pbkdf2_hmac(self, algorithm, length, salt, iterations,
                           key_material):
        for b in self._filtered_backends(PBKDF2HMACBackend):
            try:
                return b.derive_pbkdf2_hmac(
                    algorithm, length, salt, iterations, key_material
                )
            except UnsupportedAlgorithm:
                pass
        raise UnsupportedAlgorithm(
            "None of the constituents backends support this algorithm."
        )

    def generate_rsa_private_key(self, public_exponent, key_size):
        for b in self._filtered_backends(RSABackend):
            return b.generate_rsa_private_key(public_exponent, key_size)
        raise UnsupportedAlgorithm(
            "None of the constituents backends support this algorithm."
        )

    def create_rsa_signature_ctx(self, private_key, padding, algorithm):
        for b in self._filtered_backends(RSABackend):
            return b.create_rsa_signature_ctx(private_key, padding, algorithm)
        raise UnsupportedAlgorithm(
            "None of the constituents backends support this algorithm."
        )

    def create_rsa_verification_ctx(self, public_key, signature, padding,
                                    algorithm):
        for b in self._filtered_backends(RSABackend):
            return b.create_rsa_verification_ctx(public_key, signature,
                                                 padding, algorithm)
        raise UnsupportedAlgorithm(
            "None of the constituents backends support this algorithm."
        )
