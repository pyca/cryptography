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

from cryptography.hazmat.primitives.asymmetric.rsa import generate_rsa_key


# The extended euclidean algorithm is one way to calculate the private exponent
# (d) of an RSA key using the totient (p -1) * (q-1) (b below), and the public
# exponent (a below).
# See: http://en.wikipedia.org/wiki/Extended_Euclidean_algorithm#Pseudocode
def extended_euclidean(a, b):
    original_totient = b
    x = 0
    prev_x = 1
    y = 1
    prev_y = 0
    while b != 0:
        q = a // b
        a, b = b, a % b
        x, prev_x = prev_x - q * x, x
        y, prev_y = prev_y - q * y, y

    return prev_x if prev_x > 0 else original_totient + prev_x


class TestRSAPrivateKey(object):
    @pytest.mark.parametrize("key_length", [
        128, 1024, 1025, 2048
    ])
    def test_generate_key(self, backend, key_length):
        public_exponent = 65537
        key = generate_rsa_key(key_length, public_exponent, backend)
        assert key.key_length == key_length
        assert key.modulus > 0
        assert key.n > 0
        assert (key.p * key.q) == key.n
        totient = (key.p - 1) * (key.q - 1)
        assert key.d == extended_euclidean(public_exponent, totient)
        assert key.public_exponent == public_exponent
        assert key.e == public_exponent

    @pytest.mark.parametrize("public_exponent", [
        3, 5, 17, 257, 65537
    ])
    def test_generate_key_alternate_exponents(self, backend, public_exponent):
        key = generate_rsa_key(768, public_exponent, backend)
        assert key.key_length == 768
        assert key.public_exponent == public_exponent
        assert key.e == public_exponent
        assert key.modulus > 0
        assert key.n > 0
        assert (key.p * key.q) == key.n
        totient = (key.p - 1) * (key.q - 1)
        assert key.d == extended_euclidean(public_exponent, totient)

    @pytest.mark.parametrize("public_exponent", [
        1, 2, 4, 8, 256, 1024
    ])
    def test_generate_key_bad_exponents(self, backend, public_exponent):
        with pytest.raises(ValueError):
            generate_rsa_key(1024, public_exponent, backend)
