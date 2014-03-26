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

import six

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.backends.interfaces import RSABackend
from cryptography.hazmat.primitives import interfaces


@utils.register_interface(interfaces.RSAPublicKey)
class RSAPublicKey(object):
    def __init__(self, public_exponent, modulus):
        if (
            not isinstance(public_exponent, six.integer_types) or
            not isinstance(modulus, six.integer_types)
        ):
            raise TypeError("RSAPublicKey arguments must be integers")

        if modulus < 3:
            raise ValueError("modulus must be >= 3")

        if public_exponent < 3 or public_exponent >= modulus:
            raise ValueError("public_exponent must be >= 3 and < modulus")

        if public_exponent & 1 == 0:
            raise ValueError("public_exponent must be odd")

        self._public_exponent = public_exponent
        self._modulus = modulus

    def verifier(self, signature, padding, algorithm, backend):
        if not isinstance(backend, RSABackend):
            raise UnsupportedAlgorithm(
                "Backend object does not implement RSABackend",
                _Reasons.BACKEND_MISSING_INTERFACE
            )

        return backend.create_rsa_verification_ctx(self, signature, padding,
                                                   algorithm)

    @property
    def key_size(self):
        return utils.bit_length(self.modulus)

    @property
    def public_exponent(self):
        return self._public_exponent

    @property
    def modulus(self):
        return self._modulus

    @property
    def e(self):
        return self.public_exponent

    @property
    def n(self):
        return self.modulus


@utils.register_interface(interfaces.RSAPrivateKey)
class RSAPrivateKey(object):
    def __init__(self, p, q, private_exponent, dmp1, dmq1, iqmp,
                 public_exponent, modulus):
        if (
            not isinstance(p, six.integer_types) or
            not isinstance(q, six.integer_types) or
            not isinstance(dmp1, six.integer_types) or
            not isinstance(dmq1, six.integer_types) or
            not isinstance(iqmp, six.integer_types) or
            not isinstance(private_exponent, six.integer_types) or
            not isinstance(public_exponent, six.integer_types) or
            not isinstance(modulus, six.integer_types)
        ):
            raise TypeError("RSAPrivateKey arguments must be integers")

        if modulus < 3:
            raise ValueError("modulus must be >= 3")

        if p >= modulus:
            raise ValueError("p must be < modulus")

        if q >= modulus:
            raise ValueError("q must be < modulus")

        if dmp1 >= modulus:
            raise ValueError("dmp1 must be < modulus")

        if dmq1 >= modulus:
            raise ValueError("dmq1 must be < modulus")

        if iqmp >= modulus:
            raise ValueError("iqmp must be < modulus")

        if private_exponent >= modulus:
            raise ValueError("private_exponent must be < modulus")

        if public_exponent < 3 or public_exponent >= modulus:
            raise ValueError("public_exponent must be >= 3 and < modulus")

        if public_exponent & 1 == 0:
            raise ValueError("public_exponent must be odd")

        if dmp1 & 1 == 0:
            raise ValueError("dmp1 must be odd")

        if dmq1 & 1 == 0:
            raise ValueError("dmq1 must be odd")

        if p * q != modulus:
            raise ValueError("p*q must equal modulus")

        self._p = p
        self._q = q
        self._dmp1 = dmp1
        self._dmq1 = dmq1
        self._iqmp = iqmp
        self._private_exponent = private_exponent
        self._public_exponent = public_exponent
        self._modulus = modulus

    @classmethod
    def generate(cls, public_exponent, key_size, backend):
        if not isinstance(backend, RSABackend):
            raise UnsupportedAlgorithm(
                "Backend object does not implement RSABackend",
                _Reasons.BACKEND_MISSING_INTERFACE
            )

        return backend.generate_rsa_private_key(public_exponent, key_size)

    def signer(self, padding, algorithm, backend):
        if not isinstance(backend, RSABackend):
            raise UnsupportedAlgorithm(
                "Backend object does not implement RSABackend",
                _Reasons.BACKEND_MISSING_INTERFACE
            )

        return backend.create_rsa_signature_ctx(self, padding, algorithm)

    @property
    def key_size(self):
        return utils.bit_length(self.modulus)

    def public_key(self):
        return RSAPublicKey(self.public_exponent, self.modulus)

    @property
    def p(self):
        return self._p

    @property
    def q(self):
        return self._q

    @property
    def private_exponent(self):
        return self._private_exponent

    @property
    def public_exponent(self):
        return self._public_exponent

    @property
    def modulus(self):
        return self._modulus

    @property
    def d(self):
        return self.private_exponent

    @property
    def dmp1(self):
        return self._dmp1

    @property
    def dmq1(self):
        return self._dmq1

    @property
    def iqmp(self):
        return self._iqmp

    @property
    def e(self):
        return self.public_exponent

    @property
    def n(self):
        return self.modulus
