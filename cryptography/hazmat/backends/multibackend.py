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
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.backends.interfaces import (
    CMACBackend, CipherBackend, DSABackend, EllipticCurveBackend, HMACBackend,
    HashBackend, PBKDF2HMACBackend, RSABackend
)


@utils.register_interface(CMACBackend)
@utils.register_interface(CipherBackend)
@utils.register_interface(HashBackend)
@utils.register_interface(HMACBackend)
@utils.register_interface(PBKDF2HMACBackend)
@utils.register_interface(RSABackend)
@utils.register_interface(DSABackend)
@utils.register_interface(EllipticCurveBackend)
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
            "cipher {0} in {1} mode is not supported by this backend.".format(
                algorithm.name, mode.name if mode else mode),
            _Reasons.UNSUPPORTED_CIPHER
        )

    def create_symmetric_decryption_ctx(self, algorithm, mode):
        for b in self._filtered_backends(CipherBackend):
            try:
                return b.create_symmetric_decryption_ctx(algorithm, mode)
            except UnsupportedAlgorithm:
                pass
        raise UnsupportedAlgorithm(
            "cipher {0} in {1} mode is not supported by this backend.".format(
                algorithm.name, mode.name if mode else mode),
            _Reasons.UNSUPPORTED_CIPHER
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
            "{0} is not a supported hash on this backend.".format(
                algorithm.name),
            _Reasons.UNSUPPORTED_HASH
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
            "{0} is not a supported hash on this backend.".format(
                algorithm.name),
            _Reasons.UNSUPPORTED_HASH
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
            "{0} is not a supported hash on this backend.".format(
                algorithm.name),
            _Reasons.UNSUPPORTED_HASH
        )

    def generate_rsa_private_key(self, public_exponent, key_size):
        for b in self._filtered_backends(RSABackend):
            return b.generate_rsa_private_key(public_exponent, key_size)
        raise UnsupportedAlgorithm("RSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def generate_rsa_parameters_supported(self, public_exponent, key_size):
        for b in self._filtered_backends(RSABackend):
            return b.generate_rsa_parameters_supported(
                public_exponent, key_size
            )
        raise UnsupportedAlgorithm("RSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def create_rsa_signature_ctx(self, private_key, padding, algorithm):
        for b in self._filtered_backends(RSABackend):
            return b.create_rsa_signature_ctx(private_key, padding, algorithm)
        raise UnsupportedAlgorithm("RSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def create_rsa_verification_ctx(self, public_key, signature, padding,
                                    algorithm):
        for b in self._filtered_backends(RSABackend):
            return b.create_rsa_verification_ctx(public_key, signature,
                                                 padding, algorithm)
        raise UnsupportedAlgorithm("RSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def mgf1_hash_supported(self, algorithm):
        for b in self._filtered_backends(RSABackend):
            return b.mgf1_hash_supported(algorithm)
        raise UnsupportedAlgorithm("RSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def decrypt_rsa(self, private_key, ciphertext, padding):
        for b in self._filtered_backends(RSABackend):
            return b.decrypt_rsa(private_key, ciphertext, padding)
        raise UnsupportedAlgorithm("RSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def encrypt_rsa(self, public_key, plaintext, padding):
        for b in self._filtered_backends(RSABackend):
            return b.encrypt_rsa(public_key, plaintext, padding)
        raise UnsupportedAlgorithm("RSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def rsa_padding_supported(self, padding):
        for b in self._filtered_backends(RSABackend):
            return b.rsa_padding_supported(padding)
        raise UnsupportedAlgorithm("RSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def load_rsa_private_numbers(self, numbers):
        for b in self._filtered_backends(RSABackend):
            return b.load_rsa_private_numbers(numbers)

        raise UnsupportedAlgorithm("RSA is not supported by the backend",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def load_rsa_public_numbers(self, numbers):
        for b in self._filtered_backends(RSABackend):
            return b.load_rsa_public_numbers(numbers)

        raise UnsupportedAlgorithm("RSA is not supported by the backend",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def generate_dsa_parameters(self, key_size):
        for b in self._filtered_backends(DSABackend):
            return b.generate_dsa_parameters(key_size)
        raise UnsupportedAlgorithm("DSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def generate_dsa_private_key(self, parameters):
        for b in self._filtered_backends(DSABackend):
            return b.generate_dsa_private_key(parameters)
        raise UnsupportedAlgorithm("DSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def generate_dsa_private_key_and_parameters(self, key_size):
        for b in self._filtered_backends(DSABackend):
            return b.generate_dsa_private_key_and_parameters(key_size)
        raise UnsupportedAlgorithm("DSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def create_dsa_verification_ctx(self, public_key, signature, algorithm):
        for b in self._filtered_backends(DSABackend):
            return b.create_dsa_verification_ctx(public_key, signature,
                                                 algorithm)
        raise UnsupportedAlgorithm("DSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def create_dsa_signature_ctx(self, private_key, algorithm):
        for b in self._filtered_backends(DSABackend):
            return b.create_dsa_signature_ctx(private_key, algorithm)
        raise UnsupportedAlgorithm("DSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def dsa_hash_supported(self, algorithm):
        for b in self._filtered_backends(DSABackend):
            return b.dsa_hash_supported(algorithm)
        raise UnsupportedAlgorithm("DSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def dsa_parameters_supported(self, p, q, g):
        for b in self._filtered_backends(DSABackend):
            return b.dsa_parameters_supported(p, q, g)
        raise UnsupportedAlgorithm("DSA is not supported by the backend.",
                                   _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM)

    def cmac_algorithm_supported(self, algorithm):
        return any(
            b.cmac_algorithm_supported(algorithm)
            for b in self._filtered_backends(CMACBackend)
        )

    def create_cmac_ctx(self, algorithm):
        for b in self._filtered_backends(CMACBackend):
            try:
                return b.create_cmac_ctx(algorithm)
            except UnsupportedAlgorithm:
                pass
        raise UnsupportedAlgorithm("This backend does not support CMAC.",
                                   _Reasons.UNSUPPORTED_CIPHER)

    def elliptic_curve_supported(self, curve):
        return any(
            b.elliptic_curve_supported(curve)
            for b in self._filtered_backends(EllipticCurveBackend)
        )

    def elliptic_curve_signature_algorithm_supported(
        self, signature_algorithm, curve
    ):
        return any(
            b.elliptic_curve_signature_algorithm_supported(
                signature_algorithm, curve
            )
            for b in self._filtered_backends(EllipticCurveBackend)
        )

    def generate_elliptic_curve_private_key(self, curve):
        for b in self._filtered_backends(EllipticCurveBackend):
            try:
                return b.generate_elliptic_curve_private_key(curve)
            except UnsupportedAlgorithm:
                continue

        raise UnsupportedAlgorithm(
            "This backend does not support this elliptic curve.",
            _Reasons.UNSUPPORTED_ELLIPTIC_CURVE
        )

    def elliptic_curve_private_key_from_numbers(self, numbers):
        for b in self._filtered_backends(EllipticCurveBackend):
            try:
                return b.elliptic_curve_private_key_from_numbers(numbers)
            except UnsupportedAlgorithm:
                continue

        raise UnsupportedAlgorithm(
            "This backend does not support this elliptic curve.",
            _Reasons.UNSUPPORTED_ELLIPTIC_CURVE
        )

    def elliptic_curve_public_key_from_numbers(self, numbers):
        for b in self._filtered_backends(EllipticCurveBackend):
            try:
                return b.elliptic_curve_public_key_from_numbers(numbers)
            except UnsupportedAlgorithm:
                continue

        raise UnsupportedAlgorithm(
            "This backend does not support this elliptic curve.",
            _Reasons.UNSUPPORTED_ELLIPTIC_CURVE
        )
