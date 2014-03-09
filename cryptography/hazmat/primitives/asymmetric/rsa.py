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


def isqrt(n):
    """
    Integer square root, using Newton's method.
    """
    x = n
    y = (x + n // x) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def factor_n(n, e, d):
    """
    For an RSA private key, given N, E, and D, find P and Q.
    """
    k = 1 + (e * d) // n
    phi = (e * d - 1) // k
    m = n + 1 - phi
    root = isqrt(m**2 - 4*n)
    p = (m + root) // 2
    q = (m - root) // 2
    if p * q != n:
        raise ValueError('factorization failed')
    return p, q


def modinv(e, m):
    """
    Modular Multiplicative Inverse.  Returns x such that: (x*e) mod m == 1
    """
    x1, y1, x2, y2 = 1, 0, 0, 1
    a, b = e, m
    while b > 0:
        q, r = divmod(a, b)
        xn, yn = x1 - q * x2, y1 - q * y2
        a, b, x1, y1, x2, y2 = b, r, x2, y2, xn, yn
    return x1 % m


@utils.register_interface(interfaces.RSAPrivateKey)
class RSAPrivateKey(object):
    def __init__(self, p, q, private_exponent, dmp1, dmq1, iqmp,
                 public_exponent, modulus):
        if (
            (not isinstance(p, six.integer_types) and p is not None) or
            (not isinstance(q, six.integer_types) and q is not None) or
            (not isinstance(dmp1, six.integer_types) and dmp1 is not None) or
            (not isinstance(dmq1, six.integer_types) and dmp1 is not None) or
            (not isinstance(iqmp, six.integer_types) and iqmp is not None) or
            not isinstance(private_exponent, six.integer_types) or
            not isinstance(public_exponent, six.integer_types) or
            not isinstance(modulus, six.integer_types)
        ):
            raise TypeError("RSAPrivateKey arguments must be integers")

        if modulus < 3:
            raise ValueError("modulus must be >= 3")

        if p is not None and p >= modulus:
            raise ValueError("p must be < modulus")

        if q is not None and q >= modulus:
            raise ValueError("q must be < modulus")

        if dmp1 is not None and dmp1 >= modulus:
            raise ValueError("dmp1 must be < modulus")

        if dmq1 is not None and dmq1 >= modulus:
            raise ValueError("dmq1 must be < modulus")

        if iqmp is not None and iqmp >= modulus:
            raise ValueError("iqmp must be < modulus")

        if private_exponent >= modulus:
            raise ValueError("private_exponent must be < modulus")

        if public_exponent < 3 or public_exponent >= modulus:
            raise ValueError("public_exponent must be >= 3 and < modulus")

        if public_exponent & 1 == 0:
            raise ValueError("public_exponent must be odd")

        if dmp1 is not None and dmp1 & 1 == 0:
            raise ValueError("dmp1 must be odd")

        if dmq1 is not None and dmq1 & 1 == 0:
            raise ValueError("dmq1 must be odd")

        if p is not None and q is not None and p * q != modulus:
            raise ValueError("p*q must equal modulus")

        if p is None and q is None:
            p, q = factor_n(modulus, public_exponent, private_exponent)

        if dmp1 is None:
            dmp1 = private_exponent % (p - 1)

        if dmq1 is None:
            dmq1 = private_exponent % (q - 1)

        if iqmp is None:
            iqmp = modinv(q, p)

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
        return backend.generate_rsa_private_key(public_exponent, key_size)

    def signer(self, padding, algorithm, backend):
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
