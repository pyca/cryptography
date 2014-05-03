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
import textwrap

import pytest

from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_traditional_openssl_private_key
)

from .utils import _check_rsa_private_key, load_vectors_from_file
from ...utils import raises_unsupported_algorithm


@pytest.mark.traditional_openssl_serialization
class TestTraditionalOpenSSLSerialisation(object):
    @pytest.mark.parametrize(
        ("key_file", "password"),
        [
            ("key1.pem", b"123456"),
            ("key2.pem", b"a123456"),
            ("testrsa.pem", None),
            ("testrsa-encrypted.pem", b"password"),
        ]
    )
    def test_load_pem_rsa_private_key(self, key_file, password, backend):
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "Traditional_OpenSSL_Serialization", key_file),
            lambda pemfile: load_pem_traditional_openssl_private_key(
                pemfile.read().encode(), password, backend
            )
        )

        assert key
        assert isinstance(key, rsa.RSAPrivateKey)
        _check_rsa_private_key(key)

    @pytest.mark.parametrize(
        ("key_file", "password"),
        [
            ("dsa.1024.pem", None),
            ("dsa.2048.pem", None),
            ("dsa.3072.pem", None),
        ]
    )
    def test_load_pem_dsa_private_key(self, key_file, password, backend):
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "Traditional_OpenSSL_Serialization", key_file),
            lambda pemfile: load_pem_traditional_openssl_private_key(
                pemfile.read().encode(), password, backend
            )
        )

        assert key
        assert isinstance(key, dsa.DSAPrivateKey)

    def test_key1_pem_encrypted_values(self, backend):
        pkey = load_vectors_from_file(
            os.path.join(
                "asymmetric", "Traditional_OpenSSL_Serialization", "key1.pem"),
            lambda pemfile: load_pem_traditional_openssl_private_key(
                pemfile.read().encode(), b"123456", backend
            )
        )
        assert pkey

        assert pkey.p == int(
            "fb7d316fc51531b36d93adaefaf52db6ad5beb793d37c4cf9dfc1ddd17cfbafb",
            16
        )
        assert pkey.q == int(
            "df98264e646de9a0fbeab094e31caad5bc7adceaaae3c800ca0275dd4bb307f5",
            16
        )
        assert pkey.private_exponent == int(
            "db4848c36f478dd5d38f35ae519643b6b810d404bcb76c00e44015e56ca1cab0"
            "7bb7ae91f6b4b43fcfc82a47d7ed55b8c575152116994c2ce5325ec24313b911",
            16
        )
        assert pkey.dmp1 == int(
            "ce997f967192c2bcc3853186f1559fd355c190c58ddc15cbf5de9b6df954c727",
            16
        )
        assert pkey.dmq1 == int(
            "b018a57ab20ffaa3862435445d863369b852cf70a67c55058213e3fe10e3848d",
            16
        )
        assert pkey.iqmp == int(
            "6a8d830616924f5cf2d1bc1973f97fde6b63e052222ac7be06aa2532d10bac76",
            16
        )
        assert pkey.public_exponent == 65537
        assert pkey.modulus == int(
            "dba786074f2f0350ce1d99f5aed5b520cfe0deb5429ec8f2a88563763f566e77"
            "9814b7c310e5326edae31198eed439b845dd2db99eaa60f5c16a43f4be6bcf37",
            16
        )

    def test_unused_password(self, backend):
        key_file = os.path.join(
            "asymmetric", "Traditional_OpenSSL_Serialization", "testrsa.pem")
        password = b"this password will not be used"

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_traditional_openssl_private_key(
                    pemfile.read().encode(), password, backend
                )
            )

    def test_wrong_password(self, backend):
        key_file = os.path.join(
            "asymmetric",
            "Traditional_OpenSSL_Serialization",
            "testrsa-encrypted.pem"
        )
        password = b"this password is wrong"

        with pytest.raises(ValueError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_traditional_openssl_private_key(
                    pemfile.read().encode(), password, backend
                )
            )

    @pytest.mark.parametrize("password", [None, b""])
    def test_missing_password(self, backend, password):
        key_file = os.path.join(
            "asymmetric",
            "Traditional_OpenSSL_Serialization",
            "testrsa-encrypted.pem"
        )

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_traditional_openssl_private_key(
                    pemfile.read().encode(), password, backend
                )
            )

    def test_wrong_format(self, backend):
        key_data = b"---- NOT A KEY ----\n"

        with pytest.raises(ValueError):
            load_pem_traditional_openssl_private_key(
                key_data, None, backend
            )

        with pytest.raises(ValueError):
            load_pem_traditional_openssl_private_key(
                key_data, b"this password will not be used", backend
            )

    def test_corrupt_format(self, backend):
        # privkey.pem with a bunch of data missing.
        key_data = textwrap.dedent("""\
        -----BEGIN RSA PRIVATE KEY-----
        MIIBPAIBAAJBAKrbeqkuRk8VcRmWFmtP+LviMB3+6dizWW3DwaffznyHGAFwUJ/I
        Tv0XtbsCyl3QoyKGhrOAy3RvPK5M38iuXT0CAwEAAQJAZ3cnzaHXM/bxGaR5CR1R
        rD1qFBAVfoQFiOH9uPJgMaoAuoQEisPHVcZDKcOv4wEg6/TInAIXBnEigtqvRzuy
        mvcpHZwQJdmdHHkGKAs37Dfxi67HbkUCIQCeZGliHXFa071Fp06ZeWlR2ADonTZz
        rJBhdTe0v5pCeQIhAIZfkiGgGBX4cIuuckzEm43g9WMUjxP/0GlK39vIyihxAiEA
        mymehFRT0MvqW5xAKAx7Pgkt8HVKwVhc2LwGKHE0DZM=
        -----END RSA PRIVATE KEY-----
        """).encode()

        with pytest.raises(ValueError):
            load_pem_traditional_openssl_private_key(
                key_data, None, backend
            )

        with pytest.raises(ValueError):
            load_pem_traditional_openssl_private_key(
                key_data, b"this password will not be used", backend
            )

    def test_encrypted_corrupt_format(self, backend):
        # privkey.pem with a single bit flipped
        key_data = textwrap.dedent("""\
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: <,ENCRYPTED
        DEK-Info: AES-128-CBC,5E22A2BD85A653FB7A3ED20DE84F54CD

        hAqtb5ZkTMGcs4BBDQ1SKZzdQThWRDzEDxM3qBfjvYa35KxZ54aic013mW/lwj2I
        v5bbpOjrHYHNAiZYZ7RNb+ztbF6F/g5PA5g7mFwEq+LFBY0InIplYBSv9QtE+lot
        Dy4AlZa/+NzJwgdKDb+JVfk5SddyD4ywnyeORnMPy4xXKvjXwmW+iLibZVKsjIgw
        H8hSxcD+FhWyJm9h9uLtmpuqhQo0jTUYpnTezZx2xeVPB53Ev7YCxR9Nsgj5GsVf
        9Z/hqLB7IFgM3pa0z3PQeUIZF/cEf72fISWIOBwwkzVrPUkXWfbuWeJXQXSs3amE
        5A295jD9BQp9CY0nNFSsy+qiXWToq2xT3y5zVNEStmN0SCGNaIlUnJzL9IHW+oMI
        kPmXZMnAYBWeeCF1gf3J3aE5lZInegHNfEI0+J0LazC2aNU5Dg/BNqrmRqKWEIo/
        -----END RSA PRIVATE KEY-----
        """).encode()

        password = b"this password is wrong"

        with pytest.raises(ValueError):
            load_pem_traditional_openssl_private_key(
                key_data, None, backend
            )

        with pytest.raises(ValueError):
            load_pem_traditional_openssl_private_key(
                key_data, password, backend
            )

    def test_unsupported_key_encryption(self, backend):
        key_data = textwrap.dedent("""\
        -----BEGIN RSA PRIVATE KEY-----
        Proc-Type: 4,ENCRYPTED
        DEK-Info: FAKE-123,5E22A2BD85A653FB7A3ED20DE84F54CD

        hAqtb5ZkTMGcs4BBDQ1SKZzdQThWRDzEDxM3qBfjvYa35KxZ54aic013mW/lwj2I
        v5bbpOjrHYHNAiZYZ7RNb+ztbF6F/g5PA5g7mFwEq+LFBY0InIplYBSv9QtE+lot
        Dy4AlZa/+NzJwgdKDb+JVfk5SddyD4ywnyeORnMPy4xXKvjXwmW+iLibZVKsjIgw
        H8hSxcD+FhWyJm9h9uLtmpuqhQo0jTUYpnTezZx2xeVPB53Ev7YCxR9Nsgj5GsVf
        9Z/hqLB7IFgM3pa0z3PQeUIZF/cEf72fISWIOBwwkzVrPUkXWfbuWeJXQXSs3amE
        5A295jD9BQp9CY0nNFSsy+qiXWToq2xT3y5zVNEStmN0SCGNaIlUnJzL9IHW+oMI
        kPmXZMnAYBWeeCF1gf3J3aE5lZInegHNfEI0+J0LazC2aNU5Dg/BNqrmRqKWEIo/
        -----END RSA PRIVATE KEY-----
        """).encode()

        password = b"password"

        with raises_unsupported_algorithm(None):
            load_pem_traditional_openssl_private_key(
                key_data, password, backend
            )
