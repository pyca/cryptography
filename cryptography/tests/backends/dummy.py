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
from cryptography.exceptions import (
    UnsupportedAlgorithm, _Reasons
)
from cryptography.hazmat.backends.interfaces import (
    CMACBackend, CipherBackend, DSABackend, EllipticCurveBackend, HMACBackend,
    HashBackend, PBKDF2HMACBackend, PEMSerializationBackend,
    PKCS8SerializationBackend, RSABackend,
    TraditionalOpenSSLSerializationBackend
)
from cryptography.hazmat.primitives.asymmetric import ec


@utils.register_interface(CipherBackend)
class DummyCipherBackend(object):
    def __init__(self, supported_ciphers):
        self._ciphers = supported_ciphers

    def cipher_supported(self, cipher, mode):
        return (type(cipher), type(mode)) in self._ciphers

    def create_symmetric_encryption_ctx(self, cipher, mode):
        if not self.cipher_supported(cipher, mode):
            raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_CIPHER)

    def create_symmetric_decryption_ctx(self, cipher, mode):
        if not self.cipher_supported(cipher, mode):
            raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_CIPHER)


@utils.register_interface(HashBackend)
class DummyHashBackend(object):
    def __init__(self, supported_algorithms):
        self._algorithms = supported_algorithms

    def hash_supported(self, algorithm):
        return type(algorithm) in self._algorithms

    def create_hash_ctx(self, algorithm):
        if not self.hash_supported(algorithm):
            raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_HASH)


@utils.register_interface(HMACBackend)
class DummyHMACBackend(object):
    def __init__(self, supported_algorithms):
        self._algorithms = supported_algorithms

    def hmac_supported(self, algorithm):
        return type(algorithm) in self._algorithms

    def create_hmac_ctx(self, key, algorithm):
        if not self.hmac_supported(algorithm):
            raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_HASH)


@utils.register_interface(PBKDF2HMACBackend)
class DummyPBKDF2HMACBackend(object):
    def __init__(self, supported_algorithms):
        self._algorithms = supported_algorithms

    def pbkdf2_hmac_supported(self, algorithm):
        return type(algorithm) in self._algorithms

    def derive_pbkdf2_hmac(self, algorithm, length, salt, iterations,
                           key_material):
        if not self.pbkdf2_hmac_supported(algorithm):
            raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_HASH)


@utils.register_interface(RSABackend)
class DummyRSABackend(object):
    def generate_rsa_private_key(self, public_exponent, key_size):
        pass

    def rsa_padding_supported(self, padding):
        pass

    def generate_rsa_parameters_supported(self, public_exponent, key_size):
        pass

    def load_rsa_private_numbers(self, numbers):
        pass

    def load_rsa_public_numbers(self, numbers):
        pass


@utils.register_interface(DSABackend)
class DummyDSABackend(object):
    def generate_dsa_parameters(self, key_size):
        pass

    def generate_dsa_private_key(self, parameters):
        pass

    def generate_dsa_private_key_and_parameters(self, key_size):
        pass

    def dsa_hash_supported(self, algorithm):
        pass

    def dsa_parameters_supported(self, p, q, g):
        pass

    def load_dsa_private_numbers(self, numbers):
        pass

    def load_dsa_public_numbers(self, numbers):
        pass

    def load_dsa_parameter_numbers(self, numbers):
        pass


@utils.register_interface(CMACBackend)
class DummyCMACBackend(object):
    def __init__(self, supported_algorithms):
        self._algorithms = supported_algorithms

    def cmac_algorithm_supported(self, algorithm):
        return type(algorithm) in self._algorithms

    def create_cmac_ctx(self, algorithm):
        if not self.cmac_algorithm_supported(algorithm):
            raise UnsupportedAlgorithm("", _Reasons.UNSUPPORTED_CIPHER)


@utils.register_interface(EllipticCurveBackend)
class DummyEllipticCurveBackend(object):
    def __init__(self, supported_curves):
        self._curves = supported_curves

    def elliptic_curve_supported(self, curve):
        return any(
            isinstance(curve, curve_type)
            for curve_type in self._curves
        )

    def elliptic_curve_signature_algorithm_supported(
        self, signature_algorithm, curve
    ):
        return (
            isinstance(signature_algorithm, ec.ECDSA) and
            any(
                isinstance(curve, curve_type)
                for curve_type in self._curves
            )
        )

    def generate_elliptic_curve_private_key(self, curve):
        if not self.elliptic_curve_supported(curve):
            raise UnsupportedAlgorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE)

    def load_elliptic_curve_private_numbers(self, numbers):
        if not self.elliptic_curve_supported(numbers.public_numbers.curve):
            raise UnsupportedAlgorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE)

    def elliptic_curve_private_key_from_numbers(self, numbers):
        if not self.elliptic_curve_supported(numbers.public_numbers.curve):
            raise UnsupportedAlgorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE)

    def elliptic_curve_public_key_from_numbers(self, numbers):
        if not self.elliptic_curve_supported(numbers.curve):
            raise UnsupportedAlgorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE)

    def load_elliptic_curve_public_numbers(self, numbers):
        if not self.elliptic_curve_supported(numbers.curve):
            raise UnsupportedAlgorithm(_Reasons.UNSUPPORTED_ELLIPTIC_CURVE)


@utils.register_interface(PKCS8SerializationBackend)
class DummyPKCS8SerializationBackend(object):
    def load_pkcs8_pem_private_key(self, data, password):
        pass


@utils.register_interface(TraditionalOpenSSLSerializationBackend)
class DummyTraditionalOpenSSLSerializationBackend(object):
    def load_traditional_openssl_pem_private_key(self, data, password):
        pass


@utils.register_interface(PEMSerializationBackend)
class DummyPEMSerializationBackend(object):
    def load_pem_private_key(self, data, password):
        pass

    def load_pem_public_key(self, data):
        pass
