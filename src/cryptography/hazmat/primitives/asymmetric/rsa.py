# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import six

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.backends.interfaces import RSABackend


def generate_private_key(public_exponent, key_size, backend):
    if not isinstance(backend, RSABackend):
        raise UnsupportedAlgorithm(
            "Backend object does not implement RSABackend.",
            _Reasons.BACKEND_MISSING_INTERFACE
        )

    _verify_rsa_parameters(public_exponent, key_size)
    return backend.generate_rsa_private_key(public_exponent, key_size)


def _verify_rsa_parameters(public_exponent, key_size):
    if public_exponent < 3:
        raise ValueError("public_exponent must be >= 3.")

    if public_exponent & 1 == 0:
        raise ValueError("public_exponent must be odd.")

    if key_size < 512:
        raise ValueError("key_size must be at least 512-bits.")


def _check_private_key_components(p, q, private_exponent, dmp1, dmq1, iqmp,
                                  public_exponent, modulus):
    if modulus < 3:
        raise ValueError("modulus must be >= 3.")

    if p >= modulus:
        raise ValueError("p must be < modulus.")

    if q >= modulus:
        raise ValueError("q must be < modulus.")

    if dmp1 >= modulus:
        raise ValueError("dmp1 must be < modulus.")

    if dmq1 >= modulus:
        raise ValueError("dmq1 must be < modulus.")

    if iqmp >= modulus:
        raise ValueError("iqmp must be < modulus.")

    if private_exponent >= modulus:
        raise ValueError("private_exponent must be < modulus.")

    if public_exponent < 3 or public_exponent >= modulus:
        raise ValueError("public_exponent must be >= 3 and < modulus.")

    if public_exponent & 1 == 0:
        raise ValueError("public_exponent must be odd.")

    if dmp1 & 1 == 0:
        raise ValueError("dmp1 must be odd.")

    if dmq1 & 1 == 0:
        raise ValueError("dmq1 must be odd.")

    if p * q != modulus:
        raise ValueError("p*q must equal modulus.")


def _check_public_key_components(e, n):
    if n < 3:
        raise ValueError("n must be >= 3.")

    if e < 3 or e >= n:
        raise ValueError("e must be >= 3 and < n.")

    if e & 1 == 0:
        raise ValueError("e must be odd.")


def _modinv(e, m):
    """
    Modular Multiplicative Inverse. Returns x such that: (x*e) mod m == 1
    """
    x1, y1, x2, y2 = 1, 0, 0, 1
    a, b = e, m
    while b > 0:
        q, r = divmod(a, b)
        xn, yn = x1 - q * x2, y1 - q * y2
        a, b, x1, y1, x2, y2 = b, r, x2, y2, xn, yn
    return x1 % m


def rsa_crt_iqmp(p, q):
    """
    Compute the CRT (q ** -1) % p value from RSA primes p and q.
    """
    return _modinv(q, p)


def rsa_crt_dmp1(private_exponent, p):
    """
    Compute the CRT private_exponent % (p - 1) value from the RSA
    private_exponent and p.
    """
    return private_exponent % (p - 1)


def rsa_crt_dmq1(private_exponent, q):
    """
    Compute the CRT private_exponent % (q - 1) value from the RSA
    private_exponent and q.
    """
    return private_exponent % (q - 1)


class RSAPrivateNumbers(object):
    def __init__(self, p, q, d, dmp1, dmq1, iqmp,
                 public_numbers):
        if (
            not isinstance(p, six.integer_types) or
            not isinstance(q, six.integer_types) or
            not isinstance(d, six.integer_types) or
            not isinstance(dmp1, six.integer_types) or
            not isinstance(dmq1, six.integer_types) or
            not isinstance(iqmp, six.integer_types)
        ):
            raise TypeError(
                "RSAPrivateNumbers p, q, d, dmp1, dmq1, iqmp arguments must"
                " all be an integers."
            )

        if not isinstance(public_numbers, RSAPublicNumbers):
            raise TypeError(
                "RSAPrivateNumbers public_numbers must be an RSAPublicNumbers"
                " instance."
            )

        self._p = p
        self._q = q
        self._d = d
        self._dmp1 = dmp1
        self._dmq1 = dmq1
        self._iqmp = iqmp
        self._public_numbers = public_numbers

    p = utils.read_only_property("_p")
    q = utils.read_only_property("_q")
    d = utils.read_only_property("_d")
    dmp1 = utils.read_only_property("_dmp1")
    dmq1 = utils.read_only_property("_dmq1")
    iqmp = utils.read_only_property("_iqmp")
    public_numbers = utils.read_only_property("_public_numbers")

    def private_key(self, backend):
        return backend.load_rsa_private_numbers(self)

    def __eq__(self, other):
        if not isinstance(other, RSAPrivateNumbers):
            return NotImplemented

        return (
            self.p == other.p and
            self.q == other.q and
            self.d == other.d and
            self.dmp1 == other.dmp1 and
            self.dmq1 == other.dmq1 and
            self.iqmp == other.iqmp and
            self.public_numbers == other.public_numbers
        )

    def __ne__(self, other):
        return not self == other


class RSAPublicNumbers(object):
    def __init__(self, e, n):
        if (
            not isinstance(e, six.integer_types) or
            not isinstance(n, six.integer_types)
        ):
            raise TypeError("RSAPublicNumbers arguments must be integers.")

        self._e = e
        self._n = n

    e = utils.read_only_property("_e")
    n = utils.read_only_property("_n")

    def public_key(self, backend):
        return backend.load_rsa_public_numbers(self)

    def __repr__(self):
        return "<RSAPublicNumbers(e={0}, n={1})>".format(self._e, self._n)

    def __eq__(self, other):
        if not isinstance(other, RSAPublicNumbers):
            return NotImplemented

        return self.e == other.e and self.n == other.n

    def __ne__(self, other):
        return not self == other
