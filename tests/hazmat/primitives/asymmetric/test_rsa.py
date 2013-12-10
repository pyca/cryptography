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

import os
import pytest

from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey, RSAPrivateKey
)

from ....utils import load_file


class TestRSA(object):
    q = int("0xe30a63dced4a53d3c046092014d5042153175e05e1c1502545a2c7ee76c729d"
            "eb1d5942cdb0275164003b505cd32894fcd66c43a2b4ed6ff73baf3d9bd9da80f"
            "6b7ce91c9045cfbd921f1607cbf5477dc73b2bb7a9f41ee91498a4d0cdc041d49"
            "ee81c34284e4b57cdee2561a4d940eb7b7dc5e13b8a089a9ca50edf3d5dc16dL",
            0)

    p = int("0xf1448a9ee52d4d5b359135fe3e1576ef776bc12bbcabfda68a82dee72acefd7"
            "5f035cfdfce2ee90ba00834510228683a6af4c060aa9502ef9a2180e3dab1953f"
            "8200ad16366113f369a7dc4c29db90afe3f9e671b63bfea7a0d5e92bdd0ed78b9"
            "3f714762b6adc06dc06ccee77d946d7dc8c090e0aff62311ae742fab38f80dfL",
            0)

    m = int("0xd5f991b6079133b053a6f8eed76f1860e0c407767f2d935eddc216786ce31b6"
            "3d531da30da3d10974ab5edf4c502e2b8b0484ad922c6661cad0766acb3d4e2f0"
            "c3d18b48f5890cc463236b8c78a2cea2ee23923247aad6d5cebf0f5e00e990069"
            "b46d391ddfb94552473b233d677b38b620be4e60dd5519d489d0cf1c969756624"
            "c84d566d28281ea3e7c2d713a0d0d996eef0d04524eb753b978654652ecba8617"
            "4eb89782cdfa0fee665f468fd4165782e0c9e324942999a04b157cfe9f4f1552c"
            "16d8c90db46a91657dd9abc645d2caaa835f6a8c4d3a37b6ce1b3888e7cf42f1f"
            "58018f0efae83b2b85997f4a12e7bf8a409fab26f8a169b67359844fdf3L", 0)

    public_exponent = 65537

    @pytest.mark.parametrize(("f", "form", "password"), [
        ("pkcs1.pem", "pem", None),
        ("pkcs1-encrypted.pem", "pem", "cryptography"),
        ("pkcs1.der", "der", None),
    ])
    def test_load_pkcs1(self, backend, f, form, password):
        data = load_file(
            os.path.join("asymmetric", "RSA", "parsing", f)
        )
        key = RSAPrivateKey.from_pkcs1(backend, data, form, password)
        assert key.modulus == self.m
        assert key.public_exponent == self.public_exponent
        assert key.p == self.p
        assert key.q == self.q

    @pytest.mark.parametrize(("f", "form", "password"), [
        ("pkcs8.pem", "pem", None),
        ("pkcs8-encrypted.pem", "pem", "cryptography"),
        ("pkcs8.der", "der", None),
        ("pkcs8-encrypted.der", "der", "cryptography"),
    ])
    def test_load_pkcs8(self, backend, f, form, password):
        data = load_file(
            os.path.join("asymmetric", "RSA", "parsing", f)
        )
        key = RSAPrivateKey.from_pkcs8(backend, data, form, password)
        assert key.modulus == self.m
        assert key.public_exponent == self.public_exponent
        assert key.p == self.p
        assert key.q == self.q

    @pytest.mark.parametrize(("f", "form", "password"), [
        ("pkcs1-encrypted.pem", "pem", "cryptograph"),
    ])
    def test_load_bad_password_pkcs1(self, backend, f, form, password):
        data = load_file(
            os.path.join("asymmetric", "RSA", "parsing", f)
        )
        with pytest.raises(ValueError):
            RSAPrivateKey.from_pkcs8(backend, data, form, password)

    @pytest.mark.parametrize(("f", "form", "password"), [
        ("pkcs8-encrypted.pem", "pem", "cryptograph"),
        ("pkcs8-encrypted.der", "der", "cryptograph"),
    ])
    def test_load_bad_password_pkcs8(self, backend, f, form, password):
        data = load_file(
            os.path.join("asymmetric", "RSA", "parsing", f)
        )
        with pytest.raises(ValueError):
            RSAPrivateKey.from_pkcs8(backend, data, form, password)
