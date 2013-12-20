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

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey, generate_rsa_key,
)


class TestRSAPrivateKey(object):
    @pytest.mark.parametrize("key_length", [
        128, 1024, 1025, 2048
    ])
    def test_generate_key(self, backend, key_length):
        key = generate_rsa_key(key_length, 65537, backend)
        assert key.key_length == key_length
        assert key.modulus > 0
        assert key.n > 0
        assert (key.p * key.q) == key.n
        assert key.d > 0

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
        assert key.d > 0

    @pytest.mark.parametrize("public_exponent", [
        1, 2, 4, 8, 256, 1024
    ])
    def test_generate_key_bad_exponents(self, backend, public_exponent):
        with pytest.raises(ValueError):
            generate_rsa_key(1024, public_exponent, backend)

    def test_public_key(self, backend):
        key = generate_rsa_key(1024, 65537, backend)
        with pytest.raises(NotImplementedError):
            key.public_key

    def test_init_wrong_type(self):
        with pytest.raises(TypeError):
            RSAPrivateKey("string")
