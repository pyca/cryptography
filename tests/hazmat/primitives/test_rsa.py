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

from cryptography.hazmat.primitives.asymmetric import rsa

from ...utils import load_pkcs1_vectors, load_vectors_from_file


class TestRSA(object):
    @pytest.mark.parametrize(
        "pkcs1_example",
        load_vectors_from_file(
            "asymmetric/RSA/pkcs-1v2-1d2-vec/pss-vect.txt",
            load_pkcs1_vectors
        )
    )
    def test_load_pss_vect_example_keys(self, pkcs1_example):
        secret, public = pkcs1_example

        skey = rsa.RSAPrivateKey(**secret)
        pkey = rsa.RSAPublicKey(**public)
        pkey2 = skey.public_key()

        assert skey and pkey and pkey2

        assert skey.modulus
        assert skey.modulus == pkey.modulus
        assert skey.public_exponent == pkey.public_exponent

        assert pkey.modulus
        assert pkey.modulus == pkey2.modulus
        assert pkey.public_exponent == pkey2.public_exponent

        assert skey.key_size
        assert skey.key_size == pkey.key_size
        assert skey.key_size == pkey2.key_size

        assert skey.p * skey.q == skey.modulus

    def test_invalid_argument_types(self):
        with pytest.raises(TypeError):
            rsa.RSAPrivateKey(None, None, None, None, None)

        with pytest.raises(TypeError):
            rsa.RSAPublicKey(None, None)

    def test_invalid_argument_values(self):
        # tiny example key
        rsa.RSAPrivateKey(3, 5, 14, 8, 15)

        # modulus too small
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(3, 5, 14, 8, 2)

        # private exp too high
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(3, 5, 16, 8, 15)

        # public exp too low
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(3, 5, 14, 2, 15)

        # public exp too high
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(3, 5, 14, 16, 15)

        rsa.RSAPublicKey(8, 15)

        # modulus too small
        with pytest.raises(ValueError):
            rsa.RSAPublicKey(8, 2)

        # public exp too low
        with pytest.raises(ValueError):
            rsa.RSAPublicKey(2, 15)

        # public exp too high
        with pytest.raises(ValueError):
            rsa.RSAPublicKey(16, 15)
