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

import itertools
import os

import pytest

from cryptography.hazmat.primitives.asymmetric import rsa

from ...utils import load_pkcs1_vectors, load_vectors_from_file


def _egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = _egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def _modinv(a, m):
    g, x, y = _egcd(a, m)
    assert g == 1
    return x % m


def _check_rsa_private_key(skey):
    assert skey
    assert skey.modulus
    assert skey.public_exponent
    assert skey.private_exponent
    assert skey.p * skey.q == skey.modulus
    assert skey.key_size
    assert skey.dmp1 == skey.d % (skey.p - 1)
    assert skey.dmq1 == skey.d % (skey.q - 1)
    assert skey.iqmp == _modinv(skey.q, skey.p)

    pkey = skey.public_key()
    assert pkey
    assert skey.modulus == pkey.modulus
    assert skey.public_exponent == pkey.public_exponent
    assert skey.key_size == pkey.key_size


@pytest.mark.rsa
class TestRSA(object):
    @pytest.mark.parametrize(
        "public_exponent,key_size",
        itertools.product(
            (3, 5, 65537),
            (1024, 1025, 1026, 1027, 1028, 1029, 1030, 1031, 1536, 2048)
        )
    )
    def test_generate_rsa_keys(self, backend, public_exponent, key_size):
        skey = rsa.RSAPrivateKey.generate(public_exponent, key_size, backend)
        _check_rsa_private_key(skey)
        assert skey.key_size == key_size
        assert skey.public_exponent == public_exponent

    def test_generate_bad_rsa_key(self, backend):
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey.generate(public_exponent=1,
                                       key_size=2048,
                                       backend=backend)

        with pytest.raises(ValueError):
            rsa.RSAPrivateKey.generate(public_exponent=4,
                                       key_size=2048,
                                       backend=backend)

    def test_cant_generate_insecure_tiny_key(self, backend):
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey.generate(public_exponent=65537,
                                       key_size=511,
                                       backend=backend)

        with pytest.raises(ValueError):
            rsa.RSAPrivateKey.generate(public_exponent=65537,
                                       key_size=256,
                                       backend=backend)

    @pytest.mark.parametrize(
        "pkcs1_example",
        load_vectors_from_file(
            os.path.join(
                "asymmetric", "RSA", "pkcs-1v2-1d2-vec", "pss-vect.txt"),
            load_pkcs1_vectors
        )
    )
    def test_load_pss_vect_example_keys(self, pkcs1_example):
        secret, public = pkcs1_example

        skey = rsa.RSAPrivateKey(**secret)
        assert skey
        _check_rsa_private_key(skey)

        pkey = rsa.RSAPublicKey(**public)
        assert pkey

        pkey2 = skey.public_key()
        assert pkey2

        assert skey.modulus == pkey.modulus
        assert skey.modulus == skey.n
        assert skey.public_exponent == pkey.public_exponent
        assert skey.public_exponent == skey.e
        assert skey.private_exponent == skey.d

        assert pkey.modulus
        assert pkey.modulus == pkey2.modulus
        assert pkey.modulus == pkey.n
        assert pkey.public_exponent == pkey2.public_exponent
        assert pkey.public_exponent == pkey.e

        assert skey.key_size
        assert skey.key_size == pkey.key_size
        assert skey.key_size == pkey2.key_size

    def test_invalid_private_key_argument_types(self):
        with pytest.raises(TypeError):
            rsa.RSAPrivateKey(None, None, None, None, None, None, None, None)

    def test_invalid_public_key_argument_types(self):
        with pytest.raises(TypeError):
            rsa.RSAPublicKey(None, None)

    def test_invalid_private_key_argument_values(self):
        # Start with p=3, q=11, private_exponent=3, public_exponent=7,
        # modulus=33, dmp1=1, dmq1=3, iqmp=2. Then change one value at
        # a time to test the bounds.

        # Test a modulus < 3.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=2
            )

        # Test a modulus != p * q.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=35
            )

        # Test a p > modulus.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=37,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

        # Test a q > modulus.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=37,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

        # Test a dmp1 > modulus.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=35,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

        # Test a dmq1 > modulus.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=35,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

        # Test an iqmp > modulus.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=35,
                public_exponent=7,
                modulus=33
            )

        # Test a private_exponent > modulus
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=37,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

        # Test a public_exponent < 3
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=1,
                modulus=33
            )

        # Test a public_exponent > modulus
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=65537,
                modulus=33
            )

        # Test a public_exponent that is not odd.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=3,
                iqmp=2,
                public_exponent=6,
                modulus=33
            )

        # Test a dmp1 that is not odd.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=2,
                dmq1=3,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

        # Test a dmq1 that is not odd.
        with pytest.raises(ValueError):
            rsa.RSAPrivateKey(
                p=3,
                q=11,
                private_exponent=3,
                dmp1=1,
                dmq1=4,
                iqmp=2,
                public_exponent=7,
                modulus=33
            )

    def test_invalid_public_key_argument_values(self):
        # Start with public_exponent=7, modulus=15. Then change one value at a
        # time to test the bounds.

        # Test a modulus < 3.
        with pytest.raises(ValueError):
            rsa.RSAPublicKey(public_exponent=7, modulus=2)

        # Test a public_exponent < 3
        with pytest.raises(ValueError):
            rsa.RSAPublicKey(public_exponent=1, modulus=15)

        # Test a public_exponent > modulus
        with pytest.raises(ValueError):
            rsa.RSAPublicKey(public_exponent=17, modulus=15)

        # Test a public_exponent that is not odd.
        with pytest.raises(ValueError):
            rsa.RSAPublicKey(public_exponent=6, modulus=15)
