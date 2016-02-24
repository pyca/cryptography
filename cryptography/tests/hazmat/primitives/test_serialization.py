# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import itertools
import os
import textwrap

import pytest

from cryptography.exceptions import UnsupportedAlgorithm, _Reasons
from cryptography.hazmat.backends.interfaces import (
    DERSerializationBackend, DSABackend, EllipticCurveBackend,
    PEMSerializationBackend, RSABackend
)
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption, load_der_private_key, load_der_public_key,
    load_pem_private_key, load_pem_public_key, load_ssh_public_key
)


from .test_ec import _skip_curve_unsupported
from .utils import (
    _check_dsa_private_numbers, _check_rsa_private_numbers,
    load_vectors_from_file
)
from ...utils import raises_unsupported_algorithm


@pytest.mark.requires_backend_interface(interface=DERSerializationBackend)
class TestDERSerialization(object):
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.parametrize(
        ("key_path", "password"),
        [
            (["DER_Serialization", "enc-rsa-pkcs8.der"], b"foobar"),
            (["DER_Serialization", "enc2-rsa-pkcs8.der"], b"baz"),
            (["DER_Serialization", "unenc-rsa-pkcs8.der"], None),
            (["DER_Serialization", "testrsa.der"], None),
        ]
    )
    def test_load_der_rsa_private_key(self, key_path, password, backend):
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda derfile: load_der_private_key(
                derfile.read(), password, backend
            ),
            mode="rb"
        )
        assert key
        assert isinstance(key, rsa.RSAPrivateKey)
        _check_rsa_private_numbers(key.private_numbers())

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    @pytest.mark.parametrize(
        ("key_path", "password"),
        [
            (["DER_Serialization", "unenc-dsa-pkcs8.der"], None),
            (["DER_Serialization", "dsa.1024.der"], None),
            (["DER_Serialization", "dsa.2048.der"], None),
            (["DER_Serialization", "dsa.3072.der"], None),
        ]
    )
    def test_load_der_dsa_private_key(self, key_path, password, backend):
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda derfile: load_der_private_key(
                derfile.read(), password, backend
            ),
            mode="rb"
        )
        assert key
        assert isinstance(key, dsa.DSAPrivateKey)
        _check_dsa_private_numbers(key.private_numbers())

    @pytest.mark.parametrize(
        ("key_path", "password"),
        [
            (["DER_Serialization", "ec_private_key.der"], None),
            (["DER_Serialization", "ec_private_key_encrypted.der"], b"123456"),
        ]
    )
    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    def test_load_der_ec_private_key(self, key_path, password, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda derfile: load_der_private_key(
                derfile.read(), password, backend
            ),
            mode="rb"
        )

        assert key
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp256r1"
        assert key.curve.key_size == 256

    @pytest.mark.parametrize(
        "key_path",
        [
            ["DER_Serialization", "enc-rsa-pkcs8.der"],
        ]
    )
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_wrong_password(self, key_path, backend):
        key_file = os.path.join("asymmetric", *key_path)
        password = b"this password is wrong"

        with pytest.raises(ValueError):
            load_vectors_from_file(
                key_file,
                lambda derfile: load_der_private_key(
                    derfile.read(), password, backend
                ),
                mode="rb"
            )

    @pytest.mark.parametrize(
        "key_path",
        [
            ["DER_Serialization", "unenc-rsa-pkcs8.der"]
        ]
    )
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_unused_password(self, key_path, backend):
        key_file = os.path.join("asymmetric", *key_path)
        password = b"this password will not be used"

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda derfile: load_der_private_key(
                    derfile.read(), password, backend
                ),
                mode="rb"
            )

    @pytest.mark.parametrize(
        ("key_path", "password"),
        itertools.product(
            [
                ["DER_Serialization", "enc-rsa-pkcs8.der"],
            ],
            [b"", None]
        )
    )
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_missing_password(self, key_path, password, backend):
        key_file = os.path.join("asymmetric", *key_path)

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda derfile: load_der_private_key(
                    derfile.read(), password, backend
                ),
                mode="rb"
            )

    def test_wrong_format(self, backend):
        key_data = b"---- NOT A KEY ----\n"

        with pytest.raises(ValueError):
            load_der_private_key(
                key_data, None, backend
            )

        with pytest.raises(ValueError):
            load_der_private_key(
                key_data, b"this password will not be used", backend
            )

    def test_corrupt_der_pkcs8(self, backend):
        # unenc-rsa-pkcs8 with a bunch of data missing.
        key_data = textwrap.dedent("""\
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
        """).encode()
        bad_der = base64.b64decode(b"".join(key_data.splitlines()))

        with pytest.raises(ValueError):
            load_der_private_key(
                bad_der, None, backend
            )

        with pytest.raises(ValueError):
            load_der_private_key(
                bad_der, b"this password will not be used", backend
            )

    def test_corrupt_traditional_format_der(self, backend):
        # privkey with a bunch of data missing.
        key_data = textwrap.dedent("""\
        MIIBPAIBAAJBAKrbeqkuRk8VcRmWFmtP+LviMB3+6dizWW3DwaffznyHGAFwUJ/I
        Tv0XtbsCyl3QoyKGhrOAy3RvPK5M38iuXT0CAwEAAQJAZ3cnzaHXM/bxGaR5CR1R
        rD1qFBAVfoQFiOH9uPJgMaoAuoQEisPHVcZDKcOv4wEg6/TInAIXBnEigtqvRzuy
        mvcpHZwQJdmdHHkGKAs37Dfxi67HbkUCIQCeZGliHXFa071Fp06ZeWlR2ADonTZz
        rJBhdTe0v5pCeQIhAIZfkiGgGBX4cIuuckzEm43g9WMUjxP/0GlK39vIyihxAiEA
        mymehFRT0MvqW5xAKAx7Pgkt8HVKwVhc2LwGKHE0DZM=
        """).encode()
        bad_der = base64.b64decode(b"".join(key_data.splitlines()))

        with pytest.raises(ValueError):
            load_pem_private_key(bad_der, None, backend)

        with pytest.raises(ValueError):
            load_pem_private_key(
                bad_der, b"this password will not be used", backend
            )

    @pytest.mark.parametrize(
        "key_file",
        [
            os.path.join(
                "asymmetric", "DER_Serialization", "unenc-rsa-pkcs8.pub.der"),
            os.path.join(
                "asymmetric", "DER_Serialization", "rsa_public_key.der"),
            os.path.join("asymmetric", "public", "PKCS1", "rsa.pub.der"),
        ]
    )
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_load_der_rsa_public_key(self, key_file, backend):
        key = load_vectors_from_file(
            key_file,
            lambda derfile: load_der_public_key(
                derfile.read(), backend
            ),
            mode="rb"
        )
        assert key
        assert isinstance(key, rsa.RSAPublicKey)
        numbers = key.public_numbers()
        assert numbers.e == 65537

    def test_load_der_invalid_public_key(self, backend):
        with pytest.raises(ValueError):
            load_der_public_key(b"invalid data", backend)

    @pytest.mark.parametrize(
        "key_file",
        [
            os.path.join(
                "asymmetric", "DER_Serialization", "unenc-dsa-pkcs8.pub.der"),
            os.path.join(
                "asymmetric", "DER_Serialization", "dsa_public_key.der"),
        ]
    )
    @pytest.mark.requires_backend_interface(interface=DSABackend)
    def test_load_der_dsa_public_key(self, key_file, backend):
        key = load_vectors_from_file(
            key_file,
            lambda derfile: load_der_public_key(
                derfile.read(), backend
            ),
            mode="rb"
        )
        assert key
        assert isinstance(key, dsa.DSAPublicKey)

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    def test_load_ec_public_key(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "DER_Serialization",
                "ec_public_key.der"),
            lambda derfile: load_der_public_key(
                derfile.read(), backend
            ),
            mode="rb"
        )
        assert key
        assert isinstance(key, ec.EllipticCurvePublicKey)
        assert key.curve.name == "secp256r1"
        assert key.curve.key_size == 256


@pytest.mark.requires_backend_interface(interface=PEMSerializationBackend)
class TestPEMSerialization(object):
    @pytest.mark.parametrize(
        ("key_file", "password"),
        [
            (["PEM_Serialization", "rsa_private_key.pem"], b"123456"),
            (["PKCS8", "unenc-rsa-pkcs8.pem"], None),
            (["PKCS8", "enc-rsa-pkcs8.pem"], b"foobar"),
            (["PKCS8", "enc2-rsa-pkcs8.pem"], b"baz"),
            (["PKCS8", "pkcs12_s2k_pem-X_9607.pem"], b"123456"),
            (["PKCS8", "pkcs12_s2k_pem-X_9671.pem"], b"123456"),
            (["PKCS8", "pkcs12_s2k_pem-X_9925.pem"], b"123456"),
            (["PKCS8", "pkcs12_s2k_pem-X_9926.pem"], b"123456"),
            (["PKCS8", "pkcs12_s2k_pem-X_9927.pem"], b"123456"),
            (["PKCS8", "pkcs12_s2k_pem-X_9928.pem"], b"123456"),
            (["PKCS8", "pkcs12_s2k_pem-X_9929.pem"], b"123456"),
            (["PKCS8", "pkcs12_s2k_pem-X_9930.pem"], b"123456"),
            (["PKCS8", "pkcs12_s2k_pem-X_9931.pem"], b"123456"),
            (["PKCS8", "pkcs12_s2k_pem-X_9932.pem"], b"123456"),
            (["Traditional_OpenSSL_Serialization", "key1.pem"], b"123456"),
            (["Traditional_OpenSSL_Serialization", "key2.pem"], b"a123456"),
            (["Traditional_OpenSSL_Serialization", "testrsa.pem"], None),
            (["Traditional_OpenSSL_Serialization", "testrsa-encrypted.pem"],
             b"password"),
        ]
    )
    def test_load_pem_rsa_private_key(self, key_file, password, backend):
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_file),
            lambda pemfile: load_pem_private_key(
                pemfile.read().encode(), password, backend
            )
        )

        assert key
        assert isinstance(key, rsa.RSAPrivateKey)
        _check_rsa_private_numbers(key.private_numbers())

    @pytest.mark.parametrize(
        ("key_path", "password"),
        [
            (["Traditional_OpenSSL_Serialization", "dsa.1024.pem"], None),
            (["Traditional_OpenSSL_Serialization", "dsa.2048.pem"], None),
            (["Traditional_OpenSSL_Serialization", "dsa.3072.pem"], None),
            (["PKCS8", "unenc-dsa-pkcs8.pem"], None),
            (["PEM_Serialization", "dsa_private_key.pem"], b"123456"),
        ]
    )
    def test_load_dsa_private_key(self, key_path, password, backend):
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda pemfile: load_pem_private_key(
                pemfile.read().encode(), password, backend
            )
        )
        assert key
        assert isinstance(key, dsa.DSAPrivateKey)
        _check_dsa_private_numbers(key.private_numbers())

    @pytest.mark.parametrize(
        ("key_path", "password"),
        [
            (["PKCS8", "ec_private_key.pem"], None),
            (["PKCS8", "ec_private_key_encrypted.pem"], b"123456"),
            (["PEM_Serialization", "ec_private_key.pem"], None),
            (["PEM_Serialization", "ec_private_key_encrypted.pem"], b"123456"),
        ]
    )
    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    def test_load_pem_ec_private_key(self, key_path, password, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda pemfile: load_pem_private_key(
                pemfile.read().encode(), password, backend
            )
        )

        assert key
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp256r1"
        assert key.curve.key_size == 256

    @pytest.mark.parametrize(
        ("key_file"),
        [
            os.path.join("asymmetric", "PKCS8", "unenc-rsa-pkcs8.pub.pem"),
            os.path.join(
                "asymmetric", "PEM_Serialization", "rsa_public_key.pem"),
            os.path.join("asymmetric", "public", "PKCS1", "rsa.pub.pem"),
        ]
    )
    def test_load_pem_rsa_public_key(self, key_file, backend):
        key = load_vectors_from_file(
            key_file,
            lambda pemfile: load_pem_public_key(
                pemfile.read().encode(), backend
            )
        )
        assert key
        assert isinstance(key, rsa.RSAPublicKey)
        numbers = key.public_numbers()
        assert numbers.e == 65537

    @pytest.mark.parametrize(
        ("key_file"),
        [
            os.path.join("asymmetric", "PKCS8", "unenc-dsa-pkcs8.pub.pem"),
            os.path.join(
                "asymmetric", "PEM_Serialization",
                "dsa_public_key.pem"),
        ]
    )
    def test_load_pem_dsa_public_key(self, key_file, backend):
        key = load_vectors_from_file(
            key_file,
            lambda pemfile: load_pem_public_key(
                pemfile.read().encode(), backend
            )
        )
        assert key
        assert isinstance(key, dsa.DSAPublicKey)

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    def test_load_ec_public_key(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PEM_Serialization",
                "ec_public_key.pem"),
            lambda pemfile: load_pem_public_key(
                pemfile.read().encode(), backend
            )
        )
        assert key
        assert isinstance(key, ec.EllipticCurvePublicKey)
        assert key.curve.name == "secp256r1"
        assert key.curve.key_size == 256

    def test_rsa_traditional_encrypted_values(self, backend):
        pkey = load_vectors_from_file(
            os.path.join(
                "asymmetric", "Traditional_OpenSSL_Serialization", "key1.pem"),
            lambda pemfile: load_pem_private_key(
                pemfile.read().encode(), b"123456", backend
            )
        )
        assert pkey

        numbers = pkey.private_numbers()
        assert numbers.p == int(
            "fb7d316fc51531b36d93adaefaf52db6ad5beb793d37c4cf9dfc1ddd17cfbafb",
            16
        )
        assert numbers.q == int(
            "df98264e646de9a0fbeab094e31caad5bc7adceaaae3c800ca0275dd4bb307f5",
            16
        )
        assert numbers.d == int(
            "db4848c36f478dd5d38f35ae519643b6b810d404bcb76c00e44015e56ca1cab0"
            "7bb7ae91f6b4b43fcfc82a47d7ed55b8c575152116994c2ce5325ec24313b911",
            16
        )
        assert numbers.dmp1 == int(
            "ce997f967192c2bcc3853186f1559fd355c190c58ddc15cbf5de9b6df954c727",
            16
        )
        assert numbers.dmq1 == int(
            "b018a57ab20ffaa3862435445d863369b852cf70a67c55058213e3fe10e3848d",
            16
        )
        assert numbers.iqmp == int(
            "6a8d830616924f5cf2d1bc1973f97fde6b63e052222ac7be06aa2532d10bac76",
            16
        )
        assert numbers.public_numbers.e == 65537
        assert numbers.public_numbers.n == int(
            "dba786074f2f0350ce1d99f5aed5b520cfe0deb5429ec8f2a88563763f566e77"
            "9814b7c310e5326edae31198eed439b845dd2db99eaa60f5c16a43f4be6bcf37",
            16
        )

    @pytest.mark.parametrize(
        "key_path",
        [
            ["Traditional_OpenSSL_Serialization", "testrsa.pem"],
            ["PKCS8", "unenc-rsa-pkcs8.pem"]
        ]
    )
    def test_unused_password(self, key_path, backend):
        key_file = os.path.join("asymmetric", *key_path)
        password = b"this password will not be used"

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_private_key(
                    pemfile.read().encode(), password, backend
                )
            )

    @pytest.mark.parametrize(
        "key_path",
        [
            ["Traditional_OpenSSL_Serialization", "testrsa-encrypted.pem"],
            ["PKCS8", "enc-rsa-pkcs8.pem"]
        ]
    )
    def test_wrong_password(self, key_path, backend):
        key_file = os.path.join("asymmetric", *key_path)
        password = b"this password is wrong"

        with pytest.raises(ValueError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_private_key(
                    pemfile.read().encode(), password, backend
                )
            )

    @pytest.mark.parametrize(
        ("key_path", "password"),
        itertools.product(
            [
                ["Traditional_OpenSSL_Serialization",
                 "testrsa-encrypted.pem"],
                ["PKCS8", "enc-rsa-pkcs8.pem"],
            ],
            [b"", None]
        )
    )
    def test_missing_password(self, key_path, password, backend):
        key_file = os.path.join("asymmetric", *key_path)

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_private_key(
                    pemfile.read().encode(), password, backend
                )
            )

    def test_wrong_private_format(self, backend):
        key_data = b"---- NOT A KEY ----\n"

        with pytest.raises(ValueError):
            load_pem_private_key(
                key_data, None, backend
            )

        with pytest.raises(ValueError):
            load_pem_private_key(
                key_data, b"this password will not be used", backend
            )

    def test_wrong_public_format(self, backend):
        key_data = b"---- NOT A KEY ----\n"

        with pytest.raises(ValueError):
            load_pem_public_key(key_data, backend)

    def test_corrupt_traditional_format(self, backend):
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
            load_pem_private_key(
                key_data, None, backend
            )

        with pytest.raises(ValueError):
            load_pem_private_key(
                key_data, b"this password will not be used", backend
            )

    def test_traditional_encrypted_corrupt_format(self, backend):
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
            load_pem_private_key(
                key_data, None, backend
            )

        with pytest.raises(ValueError):
            load_pem_private_key(
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

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            load_pem_private_key(
                key_data, password, backend
            )

    def test_corrupt_pkcs8_format(self, backend):
        # unenc-rsa-pkcs8.pem with a bunch of data missing.
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
            load_pem_private_key(
                key_data, None, backend
            )

        with pytest.raises(ValueError):
            load_pem_private_key(
                key_data, b"this password will not be used", backend
            )

    def test_pks8_encrypted_corrupt_format(self, backend):
        # enc-rsa-pkcs8.pem with some bits flipped.
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
            load_pem_private_key(
                key_data, None, backend
            )

        with pytest.raises(ValueError):
            load_pem_private_key(
                key_data, password, backend
            )

    def test_rsa_pkcs8_encrypted_values(self, backend):
        pkey = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "enc-rsa-pkcs8.pem"),
            lambda pemfile: load_pem_private_key(
                pemfile.read().encode(), b"foobar", backend
            )
        )
        assert pkey

        numbers = pkey.private_numbers()

        assert numbers.public_numbers.n == int(
            "00beec64d6db5760ac2fd4c971145641b9bd7f5c56558ece608795c79807"
            "376a7fe5b19f95b35ca358ea5c8abd7ae051d49cd2f1e45969a1ae945460"
            "3c14b278664a0e414ebc8913acb6203626985525e17a600611b028542dd0"
            "562aad787fb4f1650aa318cdcff751e1b187cbf6785fbe164e9809491b95"
            "dd68480567c99b1a57", 16
        )

        assert numbers.public_numbers.e == 65537

        assert numbers.d == int(
            "0cfe316e9dc6b8817f4fcfd5ae38a0886f68f773b8a6db4c9e6d8703c599"
            "f3d9785c3a2c09e4c8090909fb3721e19a3009ec21221523a729265707a5"
            "8f13063671c42a4096cad378ef2510cb59e23071489d8893ac4934dd149f"
            "34f2d094bea57f1c8027c3a77248ac9b91218737d0c3c3dfa7d7829e6977"
            "cf7d995688c86c81", 16
        )

        assert numbers.p == int(
            "00db122ac857b2c0437d7616daa98e597bb75ca9ad3a47a70bec10c10036"
            "03328794b225c8e3eee6ffd3fd6d2253d28e071fe27d629ab072faa14377"
            "ce6118cb67", 16
        )

        assert numbers.q == int(
            "00df1b8aa8506fcbbbb9d00257f2975e38b33d2698fd0f37e82d7ef38c56"
            "f21b6ced63c825383782a7115cfcc093300987dbd2853b518d1c8f26382a"
            "2d2586d391", 16
        )

        assert numbers.dmp1 == int(
            "00be18aca13e60712fdf5daa85421eb10d86d654b269e1255656194fb0c4"
            "2dd01a1070ea12c19f5c39e09587af02f7b1a1030d016a9ffabf3b36d699"
            "ceaf38d9bf", 16
        )

        assert numbers.dmq1 == int(
            "71aa8978f90a0c050744b77cf1263725b203ac9f730606d8ae1d289dce4a"
            "28b8d534e9ea347aeb808c73107e583eb80c546d2bddadcdb3c82693a4c1"
            "3d863451", 16
        )

        assert numbers.iqmp == int(
            "136b7b1afac6e6279f71b24217b7083485a5e827d156024609dae39d48a6"
            "bdb55af2f062cc4a3b077434e6fffad5faa29a2b5dba2bed3e4621e478c0"
            "97ccfe7f", 16
        )

    def test_load_pem_dsa_private_key(self, backend):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "unenc-dsa-pkcs8.pem"),
            lambda pemfile: load_pem_private_key(
                pemfile.read().encode(), None, backend
            )
        )
        assert key
        assert isinstance(key, dsa.DSAPrivateKey)

        params = key.parameters()
        assert isinstance(params, dsa.DSAParameters)

        num = key.private_numbers()
        pub = num.public_numbers
        parameter_numbers = pub.parameter_numbers
        assert num.x == int("00a535a8e1d0d91beafc8bee1d9b2a3a8de3311203",
                            16)
        assert pub.y == int(
            "2b260ea97dc6a12ae932c640e7df3d8ff04a8a05a0324f8d5f1b23f15fa1"
            "70ff3f42061124eff2586cb11b49a82dcdc1b90fc6a84fb10109cb67db5d"
            "2da971aeaf17be5e37284563e4c64d9e5fc8480258b319f0de29d54d8350"
            "70d9e287914d77df81491f4423b62da984eb3f45eb2a29fcea5dae525ac6"
            "ab6bcce04bfdf5b6",
            16
        )

        assert parameter_numbers.p == int(
            "00aa0930cc145825221caffa28ac2894196a27833de5ec21270791689420"
            "7774a2e7b238b0d36f1b2499a2c2585083eb01432924418d867faa212dd1"
            "071d4dceb2782794ad393cc08a4d4ada7f68d6e839a5fcd34b4e402d82cb"
            "8a8cb40fec31911bf9bd360b034caacb4c5e947992573c9e90099c1b0f05"
            "940cabe5d2de49a167",
            16
        )

        assert parameter_numbers.q == int(
            "00adc0e869b36f0ac013a681fdf4d4899d69820451", 16)

        assert parameter_numbers.g == int(
            "008c6b4589afa53a4d1048bfc346d1f386ca75521ccf72ddaa251286880e"
            "e13201ff48890bbfc33d79bacaec71e7a778507bd5f1a66422e39415be03"
            "e71141ba324f5b93131929182c88a9fa4062836066cebe74b5c6690c7d10"
            "1106c240ab7ebd54e4e3301fd086ce6adac922fb2713a2b0887cba13b9bc"
            "68ce5cfff241cd3246",
            16
        )

    @pytest.mark.parametrize(
        ("key_file", "password"),
        [
            ("bad-oid-dsa-key.pem", None),
        ]
    )
    def test_load_bad_oid_key(self, key_file, password, backend):
        with raises_unsupported_algorithm(
            _Reasons.UNSUPPORTED_PUBLIC_KEY_ALGORITHM
        ):
            load_vectors_from_file(
                os.path.join(
                    "asymmetric", "PKCS8", key_file),
                lambda pemfile: load_pem_private_key(
                    pemfile.read().encode(), password, backend
                )
            )

    @pytest.mark.parametrize(
        ("key_file", "password"),
        [
            ("bad-encryption-oid.pem", b"password"),
        ]
    )
    def test_load_bad_encryption_oid_key(self, key_file, password, backend):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_CIPHER):
            load_vectors_from_file(
                os.path.join(
                    "asymmetric", "PKCS8", key_file),
                lambda pemfile: load_pem_private_key(
                    pemfile.read().encode(), password, backend
                )
            )


@pytest.mark.requires_backend_interface(interface=RSABackend)
class TestRSASSHSerialization(object):
    def test_load_ssh_public_key_unsupported(self, backend):
        ssh_key = b'ecdsa-sha2-junk AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY='

        with pytest.raises(UnsupportedAlgorithm):
            load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_bad_format(self, backend):
        ssh_key = b'ssh-rsa not-a-real-key'

        with pytest.raises(ValueError):
            load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_rsa_too_short(self, backend):
        ssh_key = b'ssh-rsa'

        with pytest.raises(ValueError):
            load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_rsa_comment_with_spaces(self, backend):
        ssh_key = (
            b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDu/XRP1kyK6Cgt36gts9XAk"
            b"FiiuJLW6RU0j3KKVZSs1I7Z3UmU9/9aVh/rZV43WQG8jaR6kkcP4stOR0DEtll"
            b"PDA7ZRBnrfiHpSQYQ874AZaAoIjgkv7DBfsE6gcDQLub0PFjWyrYQUJhtOLQEK"
            b"vY/G0vt2iRL3juawWmCFdTK3W3XvwAdgGk71i6lHt+deOPNEPN2H58E4odrZ2f"
            b"sxn/adpDqfb2sM0kPwQs0aWvrrKGvUaustkivQE4XWiSFnB0oJB/lKK/CKVKuy"
            b"///ImSCGHQRvhwariN2tvZ6CBNSLh3iQgeB0AkyJlng7MXB2qYq/Ci2FUOryCX"
            # Extra section appended
            b"2MzHvnbv testkey@localhost extra"
        )

        load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_rsa_extra_data_after_modulo(self, backend):
        ssh_key = (
            b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDu/XRP1kyK6Cgt36gts9XAk"
            b"FiiuJLW6RU0j3KKVZSs1I7Z3UmU9/9aVh/rZV43WQG8jaR6kkcP4stOR0DEtll"
            b"PDA7ZRBnrfiHpSQYQ874AZaAoIjgkv7DBfsE6gcDQLub0PFjWyrYQUJhtOLQEK"
            b"vY/G0vt2iRL3juawWmCFdTK3W3XvwAdgGk71i6lHt+deOPNEPN2H58E4odrZ2f"
            b"sxn/adpDqfb2sM0kPwQs0aWvrrKGvUaustkivQE4XWiSFnB0oJB/lKK/CKVKuy"
            b"///ImSCGHQRvhwariN2tvZ6CBNSLh3iQgeB0AkyJlng7MXB2qYq/Ci2FUOryCX"
            b"2MzHvnbvAQ== testkey@localhost"
        )

        with pytest.raises(ValueError):
            load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_rsa_different_string(self, backend):
        ssh_key = (
            # "AAAAB3NzA" the final A is capitalized here to cause the string
            # ssh-rsa inside the base64 encoded blob to be incorrect. It should
            # be a lower case 'a'.
            b"ssh-rsa AAAAB3NzAC1yc2EAAAADAQABAAABAQDDu/XRP1kyK6Cgt36gts9XAk"
            b"FiiuJLW6RU0j3KKVZSs1I7Z3UmU9/9aVh/rZV43WQG8jaR6kkcP4stOR0DEtll"
            b"PDA7ZRBnrfiHpSQYQ874AZaAoIjgkv7DBfsE6gcDQLub0PFjWyrYQUJhtOLQEK"
            b"vY/G0vt2iRL3juawWmCFdTK3W3XvwAdgGk71i6lHt+deOPNEPN2H58E4odrZ2f"
            b"sxn/adpDqfb2sM0kPwQs0aWvrrKGvUaustkivQE4XWiSFnB0oJB/lKK/CKVKuy"
            b"///ImSCGHQRvhwariN2tvZ6CBNSLh3iQgeB0AkyJlng7MXB2qYq/Ci2FUOryCX"
            b"2MzHvnbvAQ== testkey@localhost"
        )
        with pytest.raises(ValueError):
            load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_rsa(self, backend):
        ssh_key = (
            b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDDu/XRP1kyK6Cgt36gts9XAk"
            b"FiiuJLW6RU0j3KKVZSs1I7Z3UmU9/9aVh/rZV43WQG8jaR6kkcP4stOR0DEtll"
            b"PDA7ZRBnrfiHpSQYQ874AZaAoIjgkv7DBfsE6gcDQLub0PFjWyrYQUJhtOLQEK"
            b"vY/G0vt2iRL3juawWmCFdTK3W3XvwAdgGk71i6lHt+deOPNEPN2H58E4odrZ2f"
            b"sxn/adpDqfb2sM0kPwQs0aWvrrKGvUaustkivQE4XWiSFnB0oJB/lKK/CKVKuy"
            b"///ImSCGHQRvhwariN2tvZ6CBNSLh3iQgeB0AkyJlng7MXB2qYq/Ci2FUOryCX"
            b"2MzHvnbv testkey@localhost"
        )

        key = load_ssh_public_key(ssh_key, backend)

        assert key is not None
        assert isinstance(key, rsa.RSAPublicKey)

        numbers = key.public_numbers()

        expected_e = 0x10001
        expected_n = int(
            '00C3BBF5D13F59322BA0A0B77EA0B6CF570241628AE24B5BA454D'
            '23DCA295652B3523B67752653DFFD69587FAD9578DD6406F23691'
            'EA491C3F8B2D391D0312D9653C303B651067ADF887A5241843CEF'
            '8019680A088E092FEC305FB04EA070340BB9BD0F1635B2AD84142'
            '61B4E2D010ABD8FC6D2FB768912F78EE6B05A60857532B75B75EF'
            'C007601A4EF58BA947B7E75E38F3443CDD87E7C138A1DAD9D9FB3'
            '19FF69DA43A9F6F6B0CD243F042CD1A5AFAEB286BD46AEB2D922B'
            'D01385D6892167074A0907F94A2BF08A54ABB2FFFFC89920861D0'
            '46F8706AB88DDADBD9E8204D48B87789081E074024C8996783B31'
            '7076A98ABF0A2D8550EAF2097D8CCC7BE76EF', 16)

        expected = rsa.RSAPublicNumbers(expected_e, expected_n)

        assert numbers == expected


@pytest.mark.requires_backend_interface(interface=DSABackend)
class TestDSSSSHSerialization(object):
    def test_load_ssh_public_key_dss_too_short(self, backend):
        ssh_key = b'ssh-dss'

        with pytest.raises(ValueError):
            load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_dss_comment_with_spaces(self, backend):
        ssh_key = (
            b"ssh-dss AAAAB3NzaC1kc3MAAACBALmwUtfwdjAUjU2Dixd5DvT0NDcjjr69UD"
            b"LqSD/Xt5Al7D3GXr1WOrWGpjO0NE9qzRCvMTU7zykRH6XjuNXB6Hvv48Zfm4vm"
            b"nHQHFmmMg2bI75JbnOwdzWnnPZJrVU4rS23dFFPqs5ug+EbhVVrcwzxahjcSjJ"
            b"7WEQSkVQWnSPbbAAAAFQDXmpD3DIkGvLSBf1GdUF4PHKtUrQAAAIB/bJFwss+2"
            b"fngmfG/Li5OyL7A9iVoGdkUaFaxEUROTp7wkm2z49fXFAir+/U31v50Tu98YLf"
            b"WvKlxdHcdgQYV9Ww5LIrhWwwD4UKOwC6w5S3KHVbi3pWUi7vxJFXOWfeu1mC/J"
            b"TWqMKR91j+rmOtdppWIZRyIVIqLcMdGO3m+2VgAAAIANFDz5KQH5NvoljpoRQi"
            b"RgyPjxWXiE7vjLElKj4v8KrpanAywBzdhIW1y/tzpGuwRwj5ihi8iNTHgSsoTa"
            b"j5AG5HPomJf5vJElxpu/2O9pHA52wcNObIQ7j+JA5uWusxNIbl+pF6sSiP8abr"
            b"z53N7tPF/IhHTjBHb1Ol7IFu9p9A== testkey@localhost extra"
        )

        load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_dss_extra_data_after_modulo(self, backend):
        ssh_key = (
            b"ssh-dss AAAAB3NzaC1kc3MAAACBALmwUtfwdjAUjU2Dixd5DvT0NDcjjr69UD"
            b"LqSD/Xt5Al7D3GXr1WOrWGpjO0NE9qzRCvMTU7zykRH6XjuNXB6Hvv48Zfm4vm"
            b"nHQHFmmMg2bI75JbnOwdzWnnPZJrVU4rS23dFFPqs5ug+EbhVVrcwzxahjcSjJ"
            b"7WEQSkVQWnSPbbAAAAFQDXmpD3DIkGvLSBf1GdUF4PHKtUrQAAAIB/bJFwss+2"
            b"fngmfG/Li5OyL7A9iVoGdkUaFaxEUROTp7wkm2z49fXFAir+/U31v50Tu98YLf"
            b"WvKlxdHcdgQYV9Ww5LIrhWwwD4UKOwC6w5S3KHVbi3pWUi7vxJFXOWfeu1mC/J"
            b"TWqMKR91j+rmOtdppWIZRyIVIqLcMdGO3m+2VgAAAIANFDz5KQH5NvoljpoRQi"
            b"RgyPjxWXiE7vjLElKj4v8KrpanAywBzdhIW1y/tzpGuwRwj5ihi8iNTHgSsoTa"
            b"j5AG5HPomJf5vJElxpu/2O9pHA52wcNObIQ7j+JA5uWusxNIbl+pF6sSiP8abr"
            b"z53N7tPF/IhHTjBHb1Ol7IFu9p9AAwMD== testkey@localhost"
        )

        with pytest.raises(ValueError):
            load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_dss_different_string(self, backend):
        ssh_key = (
            # "AAAAB3NzA" the final A is capitalized here to cause the string
            # ssh-dss inside the base64 encoded blob to be incorrect. It should
            # be a lower case 'a'.
            b"ssh-dss AAAAB3NzAC1kc3MAAACBALmwUtfwdjAUjU2Dixd5DvT0NDcjjr69UD"
            b"LqSD/Xt5Al7D3GXr1WOrWGpjO0NE9qzRCvMTU7zykRH6XjuNXB6Hvv48Zfm4vm"
            b"nHQHFmmMg2bI75JbnOwdzWnnPZJrVU4rS23dFFPqs5ug+EbhVVrcwzxahjcSjJ"
            b"7WEQSkVQWnSPbbAAAAFQDXmpD3DIkGvLSBf1GdUF4PHKtUrQAAAIB/bJFwss+2"
            b"fngmfG/Li5OyL7A9iVoGdkUaFaxEUROTp7wkm2z49fXFAir+/U31v50Tu98YLf"
            b"WvKlxdHcdgQYV9Ww5LIrhWwwD4UKOwC6w5S3KHVbi3pWUi7vxJFXOWfeu1mC/J"
            b"TWqMKR91j+rmOtdppWIZRyIVIqLcMdGO3m+2VgAAAIANFDz5KQH5NvoljpoRQi"
            b"RgyPjxWXiE7vjLElKj4v8KrpanAywBzdhIW1y/tzpGuwRwj5ihi8iNTHgSsoTa"
            b"j5AG5HPomJf5vJElxpu/2O9pHA52wcNObIQ7j+JA5uWusxNIbl+pF6sSiP8abr"
            b"z53N7tPF/IhHTjBHb1Ol7IFu9p9A== testkey@localhost"
        )
        with pytest.raises(ValueError):
            load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_dss(self, backend):
        ssh_key = (
            b"ssh-dss AAAAB3NzaC1kc3MAAACBALmwUtfwdjAUjU2Dixd5DvT0NDcjjr69UD"
            b"LqSD/Xt5Al7D3GXr1WOrWGpjO0NE9qzRCvMTU7zykRH6XjuNXB6Hvv48Zfm4vm"
            b"nHQHFmmMg2bI75JbnOwdzWnnPZJrVU4rS23dFFPqs5ug+EbhVVrcwzxahjcSjJ"
            b"7WEQSkVQWnSPbbAAAAFQDXmpD3DIkGvLSBf1GdUF4PHKtUrQAAAIB/bJFwss+2"
            b"fngmfG/Li5OyL7A9iVoGdkUaFaxEUROTp7wkm2z49fXFAir+/U31v50Tu98YLf"
            b"WvKlxdHcdgQYV9Ww5LIrhWwwD4UKOwC6w5S3KHVbi3pWUi7vxJFXOWfeu1mC/J"
            b"TWqMKR91j+rmOtdppWIZRyIVIqLcMdGO3m+2VgAAAIANFDz5KQH5NvoljpoRQi"
            b"RgyPjxWXiE7vjLElKj4v8KrpanAywBzdhIW1y/tzpGuwRwj5ihi8iNTHgSsoTa"
            b"j5AG5HPomJf5vJElxpu/2O9pHA52wcNObIQ7j+JA5uWusxNIbl+pF6sSiP8abr"
            b"z53N7tPF/IhHTjBHb1Ol7IFu9p9A== testkey@localhost"
        )

        key = load_ssh_public_key(ssh_key, backend)

        assert key is not None
        assert isinstance(key, dsa.DSAPublicKey)

        numbers = key.public_numbers()

        expected_y = int(
            "d143cf92901f936fa258e9a11422460c8f8f1597884eef8cb1252a3e2ff0aae"
            "96a7032c01cdd8485b5cbfb73a46bb04708f98a18bc88d4c7812b284da8f900"
            "6e473e89897f9bc9125c69bbfd8ef691c0e76c1c34e6c843b8fe240e6e5aeb3"
            "13486e5fa917ab1288ff1a6ebcf9dcdeed3c5fc88474e30476f53a5ec816ef6"
            "9f4", 16
        )
        expected_p = int(
            "b9b052d7f07630148d4d838b17790ef4f43437238ebebd5032ea483fd7b7902"
            "5ec3dc65ebd563ab586a633b4344f6acd10af31353bcf29111fa5e3b8d5c1e8"
            "7befe3c65f9b8be69c740716698c8366c8ef925b9cec1dcd69e73d926b554e2"
            "b4b6ddd1453eab39ba0f846e1555adcc33c5a8637128c9ed61104a45505a748"
            "f6db", 16
        )
        expected_q = 1230879958723280233885494314531920096931919647917
        expected_g = int(
            "7f6c9170b2cfb67e78267c6fcb8b93b22fb03d895a0676451a15ac44511393a"
            "7bc249b6cf8f5f5c5022afefd4df5bf9d13bbdf182df5af2a5c5d1dc7604185"
            "7d5b0e4b22b856c300f850a3b00bac394b728755b8b7a56522eefc491573967"
            "debb5982fc94d6a8c291f758feae63ad769a5621947221522a2dc31d18ede6f"
            "b656", 16
        )
        expected = dsa.DSAPublicNumbers(
            expected_y,
            dsa.DSAParameterNumbers(expected_p, expected_q, expected_g)
        )

        assert numbers == expected


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
class TestECDSASSHSerialization(object):
    def test_load_ssh_public_key_ecdsa_nist_p256(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())

        ssh_key = (
            b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy"
            b"NTYAAABBBGG2MfkHXp0UkxUyllDzWNBAImsvt5t7pFtTXegZK2WbGxml8zMrgWi5"
            b"teIg1TO03/FD9hbpBFgBeix3NrCFPls= root@cloud-server-01"
        )
        key = load_ssh_public_key(ssh_key, backend)
        assert isinstance(key, ec.EllipticCurvePublicKey)

        expected_x = int(
            "44196257377740326295529888716212621920056478823906609851236662550"
            "785814128027", 10
        )
        expected_y = int(
            "12257763433170736656417248739355923610241609728032203358057767672"
            "925775019611", 10
        )

        assert key.public_numbers() == ec.EllipticCurvePublicNumbers(
            expected_x, expected_y, ec.SECP256R1()
        )

    def test_load_ssh_public_key_ecdsa_nist_p384(self, backend):
        _skip_curve_unsupported(backend, ec.SECP384R1())
        ssh_key = (
            b"ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAz"
            b"ODQAAABhBMzucOm9wbwg4iMr5QL0ya0XNQGXpw4wM5f12E3tWhdcrzyGHyel71t1"
            b"4bvF9JZ2/WIuSxUr33XDl8jYo+lMQ5N7Vanc7f7i3AR1YydatL3wQfZStQ1I3rBa"
            b"qQtRSEU8Tg== root@cloud-server-01"
        )
        key = load_ssh_public_key(ssh_key, backend)

        expected_x = int(
            "31541830871345183397582554827482786756220448716666815789487537666"
            "592636882822352575507883817901562613492450642523901", 10
        )
        expected_y = int(
            "15111413269431823234030344298767984698884955023183354737123929430"
            "995703524272335782455051101616329050844273733614670", 10
        )

        assert key.public_numbers() == ec.EllipticCurvePublicNumbers(
            expected_x, expected_y, ec.SECP384R1()
        )

    def test_load_ssh_public_key_ecdsa_nist_p521(self, backend):
        _skip_curve_unsupported(backend, ec.SECP521R1())
        ssh_key = (
            b"ecdsa-sha2-nistp521 AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1"
            b"MjEAAACFBAGTrRhMSEgF6Ni+PXNz+5fjS4lw3ypUILVVQ0Av+0hQxOx+MyozELon"
            b"I8NKbrbBjijEs1GuImsmkTmWsMXS1j2A7wB4Kseh7W9KA9IZJ1+TMrzWUEwvOOXi"
            b"wT23pbaWWXG4NaM7vssWfZBnvz3S174TCXnJ+DSccvWBFnKP0KchzLKxbg== "
            b"root@cloud-server-01"
        )
        key = load_ssh_public_key(ssh_key, backend)

        expected_x = int(
            "54124123120178189598842622575230904027376313369742467279346415219"
            "77809037378785192537810367028427387173980786968395921877911964629"
            "142163122798974160187785455", 10
        )
        expected_y = int(
            "16111775122845033200938694062381820957441843014849125660011303579"
            "15284560361402515564433711416776946492019498546572162801954089916"
            "006665939539407104638103918", 10
        )

        assert key.public_numbers() == ec.EllipticCurvePublicNumbers(
            expected_x, expected_y, ec.SECP521R1()
        )

    def test_load_ssh_public_key_ecdsa_nist_p256_trailing_data(self, backend):
        ssh_key = (
            b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy"
            b"NTYAAABBBGG2MfkHXp0UkxUyllDzWNBAImsvt5t7pFtTXegZK2WbGxml8zMrgWi5"
            b"teIg1TO03/FD9hbpBFgBeix3NrCFPltB= root@cloud-server-01"
        )
        with pytest.raises(ValueError):
            load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_ecdsa_nist_p256_missing_data(self, backend):
        ssh_key = (
            b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy"
            b"NTYAAABBBGG2MfkHXp0UkxUyllDzWNBAImsvt5t7pFtTXegZK2WbGxml8zMrgWi5"
            b"teIg1TO03/FD9hbpBFgBeix3NrCF= root@cloud-server-01"
        )
        with pytest.raises(ValueError):
            load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_ecdsa_nist_p256_compressed(self, backend):
        # If we ever implement compressed points, note that this is not a valid
        # one, it just has the compressed marker in the right place.
        ssh_key = (
            b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy"
            b"NTYAAABBAWG2MfkHXp0UkxUyllDzWNBAImsvt5t7pFtTXegZK2WbGxml8zMrgWi5"
            b"teIg1TO03/FD9hbpBFgBeix3NrCFPls= root@cloud-server-01"
        )
        with pytest.raises(NotImplementedError):
            load_ssh_public_key(ssh_key, backend)

    def test_load_ssh_public_key_ecdsa_nist_p256_bad_curve_name(self, backend):
        ssh_key = (
            # The curve name in here is changed to be "nistp255".
            b"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAy"
            b"NTUAAABBBGG2MfkHXp0UkxUyllDzWNBAImsvt5t7pFtTXegZK2WbGxml8zMrgWi5"
            b"teIg1TO03/FD9hbpBFgBeix3NrCFPls= root@cloud-server-01"
        )
        with pytest.raises(ValueError):
            load_ssh_public_key(ssh_key, backend)


class TestKeySerializationEncryptionTypes(object):
    def test_non_bytes_password(self):
        with pytest.raises(ValueError):
            BestAvailableEncryption(object())

    def test_encryption_with_zero_length_password(self):
        with pytest.raises(ValueError):
            BestAvailableEncryption(b"")
