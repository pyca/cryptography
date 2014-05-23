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
    load_pem_pkcs8_private_key,
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


@pytest.mark.pkcs8_serialization
class TestPKCS8Serialisation(object):
    @pytest.mark.parametrize(
        ("key_file", "password"),
        [
            ("unencpkcs8.pem", None),
            ("encpkcs8.pem", b"foobar"),
            ("enc2pkcs8.pem", b"baz"),
            ("pkcs12_s2k_pem-X_9607.pem", b"123456"),
            ("pkcs12_s2k_pem-X_9671.pem", b"123456"),
            ("pkcs12_s2k_pem-X_9925.pem", b"123456"),
            ("pkcs12_s2k_pem-X_9926.pem", b"123456"),
            ("pkcs12_s2k_pem-X_9927.pem", b"123456"),
            ("pkcs12_s2k_pem-X_9928.pem", b"123456"),
            ("pkcs12_s2k_pem-X_9929.pem", b"123456"),
            ("pkcs12_s2k_pem-X_9930.pem", b"123456"),
            ("pkcs12_s2k_pem-X_9931.pem", b"123456"),
            ("pkcs12_s2k_pem-X_9932.pem", b"123456"),
        ]
    )
    def test_load_pem_rsa_private_key(self, key_file, password, backend):
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", key_file),
            lambda pemfile: load_pem_pkcs8_private_key(
                pemfile.read().encode(), password, backend
            )
        )

        assert key
        assert isinstance(key, rsa.RSAPrivateKey)
        _check_rsa_private_key(key)

    def test_unused_password(self, backend):
        key_file = os.path.join(
            "asymmetric", "PKCS8", "unencpkcs8.pem")
        password = b"this password will not be used"

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_pkcs8_private_key(
                    pemfile.read().encode(), password, backend
                )
            )

    def test_wrong_password(self, backend):
        key_file = os.path.join(
            "asymmetric", "PKCS8", "encpkcs8.pem")
        password = b"this password is wrong"

        with pytest.raises(ValueError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_pkcs8_private_key(
                    pemfile.read().encode(), password, backend
                )
            )

    @pytest.mark.parametrize("password", [None, b""])
    def test_missing_password(self, backend, password):
        key_file = os.path.join(
            "asymmetric",
            "PKCS8",
            "encpkcs8.pem"
        )

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_pkcs8_private_key(
                    pemfile.read().encode(), password, backend
                )
            )

    def test_wrong_format(self, backend):
        key_data = b"---- NOT A KEY ----\n"

        with pytest.raises(ValueError):
            load_pem_pkcs8_private_key(
                key_data, None, backend
            )

        with pytest.raises(ValueError):
            load_pem_pkcs8_private_key(
                key_data, b"this password will not be used", backend
            )

    def test_corrupt_format(self, backend):
        # unencpkcs8.pem with a bunch of data missing.
        key_data = textwrap.dedent("""\
        -----BEGIN PRIVATE KEY-----
        MIICdQIBADALBgkqhkiG9w0BAQEEggJhMIICXQIBAAKBgQC7JHoJfg6yNzLMOWet
        8Z49a4KD0dCspMAYvo2YAMB7/wdEycocujbhJ2n/seONi+5XqTqqFkM5VBl8rmkk
        FPZk/7x0xmdsTPECSWnHK+HhoaNDFPR3j8jQhVo1laxiqcEhAHegi5cwtFosuJAv
        FiRC0Cgz+frQPFQEBsAV9RuasyQxqzxrR0Ow0qncBeGBWbYE6WZhqtcLAI895b+i
        +F4lbB4iD7T9QeIDMU/aIMXA81UO4cns1z4qDAHKeyLLrPQrJ/B4X7XC+egUWm5+
        hr1qmyAMusyXIBECQQDJWZ8piluf4yrYfsJAn6hF5T4RjTztbqvO0GVG2McHY7Uj
        NPSffhzHx/ll0fQEQji+OgydCCX8o3HZrgw5YfSJAkEA7e+rqdU5nO5ZG//PSEQb
        tjLnRiTzBH/elQhtdZ5nF7pcpNTi4k13zutmKcWW4GK75azcRGJUhu1kDM7QYAOd
        SQJAVNkYcifkvna7GmooL5VYEsQsqLbM4v0NF2TIGNfG3z1MGp75KrC5LhL97MNR
        we2p/bd2k0HYyCKUGnf2nMPDiQJBAI75pwittSoE240EobUGIDTSz8CJsXIxuDmL
        z+KOpdpPRR5TQmbEMEspjsFpFymMiuYPgmihQbO2cJl1qScY5OkCQQCJ6m5tcN8l
        Xxg/SNpjEIv+qAyUD96XVlOJlOIeLHQ8kYE0C6ZA+MsqYIzgAreJk88Yn0lU/X0/
        mu/UpE/BRZmR
        -----END PRIVATE KEY-----
        """).encode()

        with pytest.raises(ValueError):
            load_pem_pkcs8_private_key(
                key_data, None, backend
            )

        with pytest.raises(ValueError):
            load_pem_pkcs8_private_key(
                key_data, b"this password will not be used", backend
            )

    def test_encrypted_corrupt_format(self, backend):
        # encpkcs8.pem with some bits flipped.
        key_data = textwrap.dedent("""\
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        MIICojAcBgoqhkiG9w0BDAEDMA4ECHK0M0+QuEL9AgIBIcSCAoDRq+KRY+0XP0tO
        lwBTzViiXSXoyNnKAZKt5r5K/fGNntv22g/1s/ZNCetrqsJDC5eMUPPacz06jFq/
        Ipsep4/OgjQ9UAOzXNrWEoNyrHnWDo7usgD3CW0mKyqER4+wG0adVMbt3N+CJHGB
        85jzRmQTfkdx1rSWeSx+XyswHn8ER4+hQ+omKWMVm7AFkjjmP/KnhUnLT98J8rhU
        ArQoFPHz/6HVkypFccNaPPNg6IA4aS2A+TU9vJYOaXSVfFB2yf99hfYYzC+ukmuU
        5Lun0cysK5s/5uSwDueUmDQKspnaNyiaMGDxvw8hilJc7vg0fGObfnbIpizhxJwq
        gKBfR7Zt0Hv8OYi1He4MehfMGdbHskztF+yQ40LplBGXQrvAqpU4zShga1BoQ98T
        0ekbBmqj7hg47VFsppXR7DKhx7G7rpMmdKbFhAZVCjae7rRGpUtD52cpFdPhMyAX
        huhMkoczwUW8B/rM4272lkHo6Br0yk/TQfTEGkvryflNVu6lniPTV151WV5U1M3o
        3G3a44eDyt7Ln+WSOpWtbPQMTrpKhur6WXgJvrpa/m02oOGdvOlDsoOCgavgQMWg
        7xKKL7620pHl7p7f/8tlE8q6vLXVvyNtAOgt/JAr2rgvrHaZSzDE0DwgCjBXEm+7
        cVMVNkHod7bLQefVanVtWqPzbmr8f7gKeuGwWSG9oew/lN2hxcLEPJHAQlnLgx3P
        0GdGjK9NvwA0EP2gYIeE4+UtSder7xQ7bVh25VB20R4TTIIs4aXXCVOoQPagnzaT
        6JLgl8FrvdfjHwIvmSOO1YMNmILBq000Q8WDqyErBDs4hsvtO6VQ4LeqJj6gClX3
        qeJNaJFu
        -----END ENCRYPTED PRIVATE KEY-----
        """).encode()

        password = b"this password is wrong"

        with pytest.raises(ValueError):
            load_pem_pkcs8_private_key(
                key_data, None, backend
            )

        with pytest.raises(ValueError):
            load_pem_pkcs8_private_key(
                key_data, password, backend
            )

    def test_key1_pem_encrypted_values(self, backend):
        pkey = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "encpkcs8.pem"),
            lambda pemfile: load_pem_pkcs8_private_key(
                pemfile.read().encode(), b"foobar", backend
            )
        )
        assert pkey

        assert pkey.modulus == int(
            "00beec64d6db5760ac2fd4c971145641b9bd7f5c56558ece608795c79807"
            "376a7fe5b19f95b35ca358ea5c8abd7ae051d49cd2f1e45969a1ae945460"
            "3c14b278664a0e414ebc8913acb6203626985525e17a600611b028542dd0"
            "562aad787fb4f1650aa318cdcff751e1b187cbf6785fbe164e9809491b95"
            "dd68480567c99b1a57", 16
        )

        assert pkey.public_exponent == 65537

        assert pkey.private_exponent == int(
            "0cfe316e9dc6b8817f4fcfd5ae38a0886f68f773b8a6db4c9e6d8703c599"
            "f3d9785c3a2c09e4c8090909fb3721e19a3009ec21221523a729265707a5"
            "8f13063671c42a4096cad378ef2510cb59e23071489d8893ac4934dd149f"
            "34f2d094bea57f1c8027c3a77248ac9b91218737d0c3c3dfa7d7829e6977"
            "cf7d995688c86c81", 16
        )

        assert pkey.p == int(
            "00db122ac857b2c0437d7616daa98e597bb75ca9ad3a47a70bec10c10036"
            "03328794b225c8e3eee6ffd3fd6d2253d28e071fe27d629ab072faa14377"
            "ce6118cb67", 16
        )

        assert pkey.q == int(
            "00df1b8aa8506fcbbbb9d00257f2975e38b33d2698fd0f37e82d7ef38c56"
            "f21b6ced63c825383782a7115cfcc093300987dbd2853b518d1c8f26382a"
            "2d2586d391", 16
        )

        assert pkey.dmp1 == int(
            "00be18aca13e60712fdf5daa85421eb10d86d654b269e1255656194fb0c4"
            "2dd01a1070ea12c19f5c39e09587af02f7b1a1030d016a9ffabf3b36d699"
            "ceaf38d9bf", 16
        )

        assert pkey.dmq1 == int(
            "71aa8978f90a0c050744b77cf1263725b203ac9f730606d8ae1d289dce4a"
            "28b8d534e9ea347aeb808c73107e583eb80c546d2bddadcdb3c82693a4c1"
            "3d863451", 16
        )

        assert pkey.iqmp == int(
            "136b7b1afac6e6279f71b24217b7083485a5e827d156024609dae39d48a6"
            "bdb55af2f062cc4a3b077434e6fffad5faa29a2b5dba2bed3e4621e478c0"
            "97ccfe7f", 16
        )
