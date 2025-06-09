# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import base64
import itertools
import os
import textwrap

import pytest

from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.decrepit.ciphers.algorithms import _DES, ARC4, RC2
from cryptography.hazmat.primitives.asymmetric import (
    dsa,
    ec,
    ed448,
    ed25519,
    rsa,
    x448,
    x25519,
)
from cryptography.hazmat.primitives.ciphers import modes
from cryptography.hazmat.primitives.hashes import MD5, SHA1
from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_der_parameters,
    load_der_private_key,
    load_der_public_key,
    load_pem_parameters,
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.primitives.serialization.pkcs12 import PBES

from ...utils import load_vectors_from_file
from .test_ec import _skip_curve_unsupported
from .test_rsa import rsa_key_2048
from .utils import _check_dsa_private_numbers, _check_rsa_private_numbers

# Make ruff happy since we're importing fixtures that pytest patches in as
# func args
__all__ = ["rsa_key_2048"]


def _skip_fips_format(key_path, password, backend):
    if backend._fips_enabled:
        if key_path[0] == "Traditional_OpenSSL_Serialization":
            pytest.skip("Traditional OpenSSL format blocked in FIPS mode")
        if (
            key_path[0] in ("PEM_Serialization", "PKCS8")
            and password is not None
        ):
            pytest.skip(
                "The encrypted PEM vectors currently have encryption "
                "that is not FIPS approved in the 3.0 provider"
            )
        if key_path[0] == "DER_Serialization" and password is not None:
            pytest.skip(
                "The encrypted PKCS8 DER vectors currently have encryption "
                "that is not FIPS approved in the 3.0 provider"
            )


class TestBufferProtocolSerialization:
    @pytest.mark.parametrize(
        ("key_path", "password"),
        [
            (["DER_Serialization", "enc-rsa-pkcs8.der"], bytearray(b"foobar")),
            (["DER_Serialization", "enc2-rsa-pkcs8.der"], bytearray(b"baz")),
            (["DER_Serialization", "unenc-rsa-pkcs8.der"], None),
            (["DER_Serialization", "testrsa.der"], None),
        ],
    )
    def test_load_der_rsa_private_key(self, key_path, password, backend):
        _skip_fips_format(key_path, password, backend)
        data = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda derfile: derfile.read(),
            mode="rb",
        )
        key = load_der_private_key(
            bytearray(data), password, unsafe_skip_rsa_key_validation=True
        )
        assert key
        assert isinstance(key, rsa.RSAPrivateKey)
        _check_rsa_private_numbers(key.private_numbers())

    @pytest.mark.parametrize(
        ("key_path", "password"),
        [
            (
                ["PEM_Serialization", "rsa_private_key.pem"],
                bytearray(b"123456"),
            ),
            (["PKCS8", "unenc-rsa-pkcs8.pem"], None),
            (["PKCS8", "enc-rsa-pkcs8.pem"], bytearray(b"foobar")),
            (["PKCS8", "enc2-rsa-pkcs8.pem"], bytearray(b"baz")),
            (
                ["Traditional_OpenSSL_Serialization", "key1.pem"],
                bytearray(b"123456"),
            ),
        ],
    )
    def test_load_pem_rsa_private_key(self, key_path, password, backend):
        _skip_fips_format(key_path, password, backend)
        data = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        key = load_pem_private_key(
            bytearray(data), password, unsafe_skip_rsa_key_validation=True
        )
        assert key
        assert isinstance(key, rsa.RSAPrivateKey)
        _check_rsa_private_numbers(key.private_numbers())


class TestDERSerialization:
    @pytest.mark.parametrize(
        ("key_path", "password"),
        [
            (["DER_Serialization", "enc-rsa-pkcs8.der"], b"foobar"),
            (["DER_Serialization", "enc2-rsa-pkcs8.der"], b"baz"),
            (["DER_Serialization", "unenc-rsa-pkcs8.der"], None),
            (["DER_Serialization", "testrsa.der"], None),
        ],
    )
    def test_load_der_rsa_private_key(self, key_path, password, backend):
        _skip_fips_format(key_path, password, backend)
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda derfile: load_der_private_key(
                derfile.read(), password, unsafe_skip_rsa_key_validation=True
            ),
            mode="rb",
        )
        assert key
        assert isinstance(key, rsa.RSAPrivateKey)
        _check_rsa_private_numbers(key.private_numbers())

    @pytest.mark.supported(
        only_if=lambda backend: backend.dsa_supported(),
        skip_message="Does not support DSA.",
    )
    @pytest.mark.parametrize(
        ("key_path", "password"),
        [
            (["DER_Serialization", "unenc-dsa-pkcs8.der"], None),
            (["DER_Serialization", "dsa.1024.der"], None),
            (["DER_Serialization", "dsa.2048.der"], None),
            (["DER_Serialization", "dsa.3072.der"], None),
        ],
    )
    def test_load_der_dsa_private_key(self, key_path, password, backend):
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda derfile: load_der_private_key(
                derfile.read(), password, backend
            ),
            mode="rb",
        )
        assert key
        assert isinstance(key, dsa.DSAPrivateKey)
        _check_dsa_private_numbers(key.private_numbers())

    @pytest.mark.parametrize(
        "key_path", [["DER_Serialization", "enc-rsa-pkcs8.der"]]
    )
    def test_password_not_bytes(self, key_path, backend):
        key_file = os.path.join("asymmetric", *key_path)
        password = "this password is not bytes"

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda derfile: load_der_private_key(
                    derfile.read(),
                    password,  # type:ignore[arg-type]
                    backend,
                ),
                mode="rb",
            )

    @pytest.mark.parametrize(
        ("key_path", "password"),
        [
            (["DER_Serialization", "ec_private_key.der"], None),
            (["DER_Serialization", "ec_private_key_encrypted.der"], b"123456"),
        ],
    )
    def test_load_der_ec_private_key(self, key_path, password, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda derfile: load_der_private_key(
                derfile.read(), password, backend
            ),
            mode="rb",
        )

        assert key
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert key.curve.name == "secp256r1"
        assert key.curve.key_size == 256

    @pytest.mark.parametrize(
        "key_path", [["DER_Serialization", "enc-rsa-pkcs8.der"]]
    )
    def test_wrong_password(self, key_path, backend):
        key_file = os.path.join("asymmetric", *key_path)
        password = b"this password is wrong"

        with pytest.raises(ValueError):
            load_vectors_from_file(
                key_file,
                lambda derfile: load_der_private_key(
                    derfile.read(), password, backend
                ),
                mode="rb",
            )

    @pytest.mark.parametrize(
        "key_path", [["DER_Serialization", "unenc-rsa-pkcs8.der"]]
    )
    def test_unused_password(self, key_path, backend):
        key_file = os.path.join("asymmetric", *key_path)
        password = b"this password will not be used"

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda derfile: load_der_private_key(
                    derfile.read(), password, backend
                ),
                mode="rb",
            )

    @pytest.mark.parametrize(
        ("key_path", "password"),
        itertools.product(
            [["DER_Serialization", "enc-rsa-pkcs8.der"]], [b"", None]
        ),
    )
    def test_missing_password(self, key_path, password, backend):
        key_file = os.path.join("asymmetric", *key_path)

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda derfile: load_der_private_key(
                    derfile.read(), password, backend
                ),
                mode="rb",
            )

    def test_wrong_format(self, backend):
        key_data = b"---- NOT A KEY ----\n"

        with pytest.raises(ValueError):
            load_der_private_key(key_data, None, backend)

        with pytest.raises(ValueError):
            load_der_private_key(
                key_data, b"this password will not be used", backend
            )

    def test_invalid_rsa_even_q(self, backend):
        data = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PEM_Serialization", "rsa-bad-1025-q-is-2.pem"
            ),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_pem_private_key(data, None)

    def test_corrupt_der_pkcs8(self, backend):
        # unenc-rsa-pkcs8 with a bunch of data missing.
        key_data = textwrap.dedent(
            """\
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
        """
        ).encode()
        bad_der = base64.b64decode(b"".join(key_data.splitlines()))

        with pytest.raises(ValueError):
            load_der_private_key(bad_der, None, backend)

        with pytest.raises(ValueError):
            load_der_private_key(
                bad_der, b"this password will not be used", backend
            )

    def test_corrupt_traditional_format_der(self, backend):
        # privkey with a bunch of data missing.
        key_data = textwrap.dedent(
            """\
        MIIBPAIBAAJBAKrbeqkuRk8VcRmWFmtP+LviMB3+6dizWW3DwaffznyHGAFwUJ/I
        Tv0XtbsCyl3QoyKGhrOAy3RvPK5M38iuXT0CAwEAAQJAZ3cnzaHXM/bxGaR5CR1R
        rD1qFBAVfoQFiOH9uPJgMaoAuoQEisPHVcZDKcOv4wEg6/TInAIXBnEigtqvRzuy
        mvcpHZwQJdmdHHkGKAs37Dfxi67HbkUCIQCeZGliHXFa071Fp06ZeWlR2ADonTZz
        rJBhdTe0v5pCeQIhAIZfkiGgGBX4cIuuckzEm43g9WMUjxP/0GlK39vIyihxAiEA
        mymehFRT0MvqW5xAKAx7Pgkt8HVKwVhc2LwGKHE0DZM=
        """
        ).encode()
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
                "asymmetric", "DER_Serialization", "unenc-rsa-pkcs8.pub.der"
            ),
            os.path.join(
                "asymmetric", "DER_Serialization", "rsa_public_key.der"
            ),
            os.path.join("asymmetric", "public", "PKCS1", "rsa.pub.der"),
        ],
    )
    def test_load_der_rsa_public_key(self, key_file, backend):
        key = load_vectors_from_file(
            key_file,
            lambda derfile: load_der_public_key(derfile.read(), backend),
            mode="rb",
        )
        assert key
        assert isinstance(key, rsa.RSAPublicKey)
        numbers = key.public_numbers()
        assert numbers.e == 65537

    def test_load_der_invalid_public_key(self, backend):
        with pytest.raises(ValueError):
            load_der_public_key(b"invalid data", backend)

    @pytest.mark.supported(
        only_if=lambda backend: backend.dsa_supported(),
        skip_message="Does not support DSA.",
    )
    @pytest.mark.parametrize(
        "key_file",
        [
            os.path.join(
                "asymmetric", "DER_Serialization", "unenc-dsa-pkcs8.pub.der"
            ),
            os.path.join(
                "asymmetric", "DER_Serialization", "dsa_public_key.der"
            ),
        ],
    )
    def test_load_der_dsa_public_key(self, key_file, backend):
        key = load_vectors_from_file(
            key_file,
            lambda derfile: load_der_public_key(derfile.read(), backend),
            mode="rb",
        )
        assert key
        assert isinstance(key, dsa.DSAPublicKey)

    def test_load_ec_public_key(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "DER_Serialization", "ec_public_key.der"
            ),
            lambda derfile: load_der_public_key(derfile.read(), backend),
            mode="rb",
        )
        assert key
        assert isinstance(key, ec.EllipticCurvePublicKey)
        assert key.curve.name == "secp256r1"
        assert key.curve.key_size == 256

    @pytest.mark.supported(
        only_if=lambda backend: backend.dh_supported(),
        skip_message="DH not supported",
    )
    def test_wrong_parameters_format(self, backend):
        param_data = b"---- NOT A KEY ----\n"

        with pytest.raises(ValueError):
            load_der_parameters(param_data, backend)

    def test_load_pkcs8_private_key_invalid_version(self):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "invalid-version.der"),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_der_private_key(data, password=None)

    def test_load_pkcs8_private_key_unknown_oid(self):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "unknown-oid.der"),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_der_private_key(data, password=None)

    @pytest.mark.skip_fips(reason="3DES is not FIPS")
    def test_load_pkcs8_private_key_3des_encryption(self):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "enc-rsa-3des.pem"),
            lambda f: load_pem_private_key(f.read(), password=b"password"),
            mode="rb",
        )
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    def test_load_pkcs8_private_key_unknown_encryption_algorithm(self):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "enc-unknown-algorithm.pem"),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_pem_private_key(data, password=b"password")

    def test_load_pkcs8_private_key_unknown_pbkdf2_prf(self):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "enc-unknown-pbkdf2-prf.pem"),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_pem_private_key(data, password=b"password")

    def test_load_pkcs8_private_key_unknown_kdf(self):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "enc-unknown-kdf.pem"),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_pem_private_key(data, password=b"password")

    @pytest.mark.skip_fips(reason="3DES unsupported in FIPS")
    def test_load_pkcs8_pbes_long_salt(self):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "rsa-pbe-3des-long-salt.pem"),
            lambda f: f.read(),
            mode="rb",
        )
        key = load_pem_private_key(
            data, password=b"password", unsafe_skip_rsa_key_validation=True
        )
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 4096
        assert key.private_numbers().public_numbers.e == 65537

    @pytest.mark.parametrize(
        "filename",
        [
            "rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha224.pem",
            "rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha384.pem",
            "rsa_pkcs8_pbes2_pbkdf2_2048_3des_sha512.pem",
        ],
    )
    @pytest.mark.skip_fips(reason="3DES unsupported in FIPS")
    def test_load_pkscs8_pbkdf_prf(self, filename: str):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", filename),
            lambda f: load_pem_private_key(f.read(), password=b"PolarSSLTest"),
            mode="rb",
        )
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    @pytest.mark.supported(
        only_if=lambda backend: backend.cipher_supported(
            RC2(b"\x00" * 16), modes.CBC(b"\x00" * 8)
        )
        and not (
            rust_openssl.CRYPTOGRAPHY_IS_BORINGSSL
            or rust_openssl.CRYPTOGRAPHY_IS_AWSLC
        ),
        skip_message="Does not support RC2 CBC",
    )
    def test_load_pkcs8_40_bit_rc2(self):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "rsa-40bitrc2.pem"),
            lambda f: load_pem_private_key(f.read(), password=b"baz"),
            mode="rb",
        )
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 1024

    @pytest.mark.supported(
        only_if=lambda backend: backend.cipher_supported(
            RC2(b"\x00" * 16), modes.CBC(b"\x00" * 8)
        )
        and not (
            rust_openssl.CRYPTOGRAPHY_IS_BORINGSSL
            or rust_openssl.CRYPTOGRAPHY_IS_AWSLC
        ),
        skip_message="Does not support RC2 CBC",
    )
    def test_load_pkcs8_rc2_cbc(self):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "rsa-rc2-cbc.pem"),
            lambda f: load_pem_private_key(
                f.read(), password=b"Red Hat Enterprise Linux 7.4"
            ),
            mode="rb",
        )
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    @pytest.mark.supported(
        only_if=lambda backend: backend.cipher_supported(
            RC2(b"\x00" * 16), modes.CBC(b"\x00" * 8)
        ),
        skip_message="Does not support RC2 CBC",
    )
    def test_load_pkcs8_rc2_cbc_effective_key_length(self):
        data = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PKCS8", "rsa-rc2-cbc-effective-key-length.pem"
            ),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_pem_private_key(data, password=b"password")

    @pytest.mark.supported(
        only_if=lambda backend: backend.cipher_supported(
            ARC4(b"\x00" * 16), None
        ),
        skip_message="Does not support RC4",
    )
    def test_load_pkcs8_rc4_sha1_128bit(self):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "enc-ec-sha1-128-rc4.pem"),
            lambda f: load_pem_private_key(f.read(), password=b"password"),
            mode="rb",
        )
        assert isinstance(key, ec.EllipticCurvePrivateKey)
        assert isinstance(key.curve, ec.SECP256R1)

    def test_load_pkcs8_aes_192_cbc(self):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "rsa-aes-192-cbc.pem"),
            lambda f: load_pem_private_key(f.read(), password=b"PolarSSLTest"),
            mode="rb",
        )
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048

    @pytest.mark.supported(
        only_if=lambda backend: backend.scrypt_supported(),
        skip_message="Scrypt required",
    )
    def test_load_pkcs8_scrypt(self):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "ed25519-scrypt.pem"),
            lambda f: load_pem_private_key(f.read(), password=b"hunter42"),
            mode="rb",
        )
        assert isinstance(key, ed25519.Ed25519PrivateKey)

    @pytest.mark.supported(
        only_if=lambda backend: backend.hash_supported(MD5())
        and backend.cipher_supported(_DES(), modes.CBC(b"\x00" * 8)),
        skip_message="Does not support DES MD5",
    )
    def test_load_pkcs8_pbe_with_md5_and_des_cbc(self):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "rsa-pbewithmd5anddescbc.pem"),
            lambda f: load_pem_private_key(f.read(), password=b"hunter2"),
            mode="rb",
        )
        assert isinstance(key, rsa.RSAPrivateKey)
        assert key.key_size == 2048


class TestPEMSerialization:
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
            (
                ["Traditional_OpenSSL_Serialization", "testrsa-encrypted.pem"],
                b"password",
            ),
        ],
    )
    def test_load_pem_rsa_private_key(self, key_file, password, backend):
        _skip_fips_format(key_file, password, backend)
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_file),
            lambda pemfile: load_pem_private_key(
                pemfile.read().encode(),
                password,
                unsafe_skip_rsa_key_validation=True,
            ),
        )

        assert key
        assert isinstance(key, rsa.RSAPrivateKey)
        _check_rsa_private_numbers(key.private_numbers())

    @pytest.mark.supported(
        only_if=lambda backend: backend.dsa_supported(),
        skip_message="Does not support DSA.",
    )
    @pytest.mark.parametrize(
        ("key_path", "password"),
        [
            (["Traditional_OpenSSL_Serialization", "dsa.1024.pem"], None),
            (["Traditional_OpenSSL_Serialization", "dsa.2048.pem"], None),
            (["Traditional_OpenSSL_Serialization", "dsa.3072.pem"], None),
            (["PKCS8", "unenc-dsa-pkcs8.pem"], None),
            (["PEM_Serialization", "dsa_private_key.pem"], b"123456"),
        ],
    )
    def test_load_dsa_private_key(self, key_path, password, backend):
        _skip_fips_format(key_path, password, backend)
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda pemfile: load_pem_private_key(
                pemfile.read().encode(), password, backend
            ),
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
        ],
    )
    def test_load_pem_ec_private_key(self, key_path, password, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        _skip_fips_format(key_path, password, backend)
        key = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda pemfile: load_pem_private_key(
                pemfile.read().encode(), password, backend
            ),
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
                "asymmetric", "PEM_Serialization", "rsa_public_key.pem"
            ),
            os.path.join("asymmetric", "public", "PKCS1", "rsa.pub.pem"),
            os.path.join(
                "asymmetric",
                "PEM_Serialization",
                "rsa_wrong_delimiter_public_key.pem",
            ),
        ],
    )
    def test_load_pem_rsa_public_key(self, key_file, backend):
        key = load_vectors_from_file(
            key_file,
            lambda pemfile: load_pem_public_key(
                pemfile.read().encode(), backend
            ),
        )
        assert key
        assert isinstance(key, rsa.RSAPublicKey)
        numbers = key.public_numbers()
        assert numbers.e == 65537

    def test_load_pem_public_fails_with_ec_key_with_rsa_delimiter(self):
        with pytest.raises(ValueError):
            load_vectors_from_file(
                os.path.join(
                    "asymmetric",
                    "PEM_Serialization",
                    "ec_public_key_rsa_delimiter.pem",
                ),
                lambda pemfile: load_pem_public_key(pemfile.read().encode()),
            )

    def test_load_priv_key_with_public_key_api_fails(
        self, rsa_key_2048, backend
    ):
        # In OpenSSL 3.0.x the PEM_read_bio_PUBKEY function will invoke
        # the default password callback if you pass an encrypted private
        # key. This is very, very, very bad as the default callback can
        # trigger an interactive console prompt, which will hang the
        # Python process. This test makes sure we don't do that.
        priv_key_serialized = rsa_key_2048.private_bytes(
            Encoding.PEM,
            PrivateFormat.PKCS8,
            BestAvailableEncryption(b"password"),
        )
        with pytest.raises(ValueError):
            load_pem_public_key(priv_key_serialized)

    @pytest.mark.supported(
        only_if=lambda backend: backend.dsa_supported(),
        skip_message="Does not support DSA.",
    )
    @pytest.mark.parametrize(
        ("key_file"),
        [
            os.path.join("asymmetric", "PKCS8", "unenc-dsa-pkcs8.pub.pem"),
            os.path.join(
                "asymmetric", "PEM_Serialization", "dsa_public_key.pem"
            ),
        ],
    )
    def test_load_pem_dsa_public_key(self, key_file, backend):
        key = load_vectors_from_file(
            key_file,
            lambda pemfile: load_pem_public_key(
                pemfile.read().encode(), backend
            ),
        )
        assert key
        assert isinstance(key, dsa.DSAPublicKey)

    def test_load_ec_public_key(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        key = load_vectors_from_file(
            os.path.join(
                "asymmetric", "PEM_Serialization", "ec_public_key.pem"
            ),
            lambda pemfile: load_pem_public_key(
                pemfile.read().encode(), backend
            ),
        )
        assert key
        assert isinstance(key, ec.EllipticCurvePublicKey)
        assert key.curve.name == "secp256r1"
        assert key.curve.key_size == 256

    @pytest.mark.skip_fips(
        reason="Traditional OpenSSL format blocked in FIPS mode"
    )
    def test_rsa_traditional_encrypted_values(self, backend):
        pkey = load_vectors_from_file(
            os.path.join(
                "asymmetric", "Traditional_OpenSSL_Serialization", "key1.pem"
            ),
            lambda pemfile: load_pem_private_key(
                pemfile.read().encode(),
                b"123456",
                unsafe_skip_rsa_key_validation=True,
            ),
        )
        assert isinstance(pkey, rsa.RSAPrivateKey)

        numbers = pkey.private_numbers()
        assert numbers.p == int(
            "f8337fbcd4b54e14d4226889725d9dc713e40c87e62ce1886a517c729b3d133d"
            "c519bfb026081788509d2b503bc0966bdc67c45771e41f9844cee1be968b3263"
            "735d6c47d981dacfde1fe2110c4acbfe656599890b8f131c20d246891959f45d"
            "06d4fadf205f94f9ea050c661efdc760d7471a1963bf16333837ef6dc4f8dbaf",
            16,
        )
        assert numbers.q == int(
            "bf8c2ad54acf67f8b687849f91ece4761901e8abc8b0bc8604f55e64ad413a62"
            "02dbb28eac0463f87811c1ca826b0eeafb53d115b50de5a775f74c5e9cf8161b"
            "fc030f5e402664388ea1ef7d0ade85559e4e68cef519cb4f582ec41f994249d8"
            "b860a7433f0612322827a87b3cc0d785075811b76bccbc90ff153a11592fa307",
            16,
        )
        assert numbers.d == int(
            "09a768d21f58866d690aeb78f0d92732aa03fa843f960b0799dfc31e7d73f1e6"
            "503953c582becd4de92d293b3a86a42b2837531fdfc54db75e0d30701801a85c"
            "120e997bce2b19290234710e2fd4cbe750d3fdaab65893c539057a21b8a2201b"
            "4e418b6dff47423905a8e0b17fdd14bd3b0834ccb0a7c203d8e62e6ab4c6552d"
            "9b777847c874e743ac15942a21816bb177919215ee235064fb0a7b3baaafac14"
            "92e29b2fc80dc16b633525d83eed73fa47a55a9894148a50358eb94c62b19e84"
            "f3d7daf866cd6a606920d54ba41d7aa648e777d5269fe00b12a8cf5ccf823f62"
            "c1e8dc442ec3a7e3356913f444919baa4a5c7299345817543b4add5f9c1a477f",
            16,
        )
        assert numbers.dmp1 == int(
            "e0cdcc51dd1b0648c9470d0608e710040359179c73778d2300a123a5ae43a84c"
            "d75c1609d6b8978fe8ec2211febcd5c186151a79d57738c2b2f7eaf1b3eb09cd"
            "97ed3328f4b1afdd7ca3c61f88d1aa6895b06b5afc742f6bd7b27d1eaa2e96ad"
            "3785ea5ff4337e7cc9609f3553b6aa42655a4a225afcf57f98d8d8ecc46e5e93",
            16,
        )
        assert numbers.dmq1 == int(
            "904aeda559429e870c315025c88e9497a644fada154795ecbb657f6305e4c22f"
            "3d09f51b66d7b3db63cfb49571e3660c7ba16b3b17f5cd0f765d0189b0636e7c"
            "4c3e9de0192112944c560e8bba996005dc4822c9ec772ee1a9832938c881d811"
            "4aeb7c74bad03efacba6fc5341b3df6695deb111e44209b68c819809a38eb017",
            16,
        )
        assert numbers.iqmp == int(
            "378a3ae1978c381dce3b486b038601cf06dfa77687fdcd2d56732380bff4f32e"
            "ec20027034bcd53be80162e4054ab7fefdbc3e5fe923aa8130d2c9ab01d6a70f"
            "da3615f066886ea610e06c29cf5c2e0649a40ca936f290b779cd9e2bc3b87095"
            "26667f75a1016e268ae3b9501ae4696ec8c1af09dc567804151fdeb1486ee512",
            16,
        )
        assert numbers.public_numbers.e == 65537
        assert numbers.public_numbers.n == int(
            "b9b651fefc4dd4c9b1c0312ee69f0803990d5a539785dd14f1f6880d9198ee1f"
            "71b3babb1ebe977786b30bea170f24b7a0e7b116f2c6908cf374923984924187"
            "86de9d4e0f5f3e56d7be9eb971d3f8a4f812057cf9f9053b829d1c54d1a340fe"
            "5c90a6e228a5871da900770141b4c6e6f298409718cb16467a4f5ff63882b204"
            "255028f49745dedc7ca4b5cba6d78acf32b650f06bf81862eda0856a14e8767e"
            "d4086342284a6f9752e96435f7119a05cc3220a954774a931dbebe1f1ab0df9d"
            "aeaedb132741c3b5c48e1a1426ccd954fb9b5140c14daec9a79be9c7c8e50610"
            "dfb489c7539999cfc14ac75765bab4ae8a8df5d96c3de34c12435b1a02cf6ec9",
            16,
        )

    @pytest.mark.parametrize(
        "key_path",
        [
            ["Traditional_OpenSSL_Serialization", "testrsa.pem"],
            ["PKCS8", "unenc-rsa-pkcs8.pem"],
        ],
    )
    def test_unused_password(self, key_path, backend):
        key_file = os.path.join("asymmetric", *key_path)
        password = b"this password will not be used"

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_private_key(
                    pemfile.read().encode(), password, backend
                ),
            )

    def test_invalid_encoding_with_traditional(self, backend):
        key_file = os.path.join(
            "asymmetric", "Traditional_OpenSSL_Serialization", "testrsa.pem"
        )
        key = load_vectors_from_file(
            key_file,
            lambda pemfile: load_pem_private_key(
                pemfile.read(), None, unsafe_skip_rsa_key_validation=True
            ),
            mode="rb",
        )

        for enc in (Encoding.OpenSSH, Encoding.Raw, Encoding.X962):
            with pytest.raises(ValueError):
                key.private_bytes(
                    enc, PrivateFormat.TraditionalOpenSSL, NoEncryption()
                )

    @pytest.mark.parametrize(
        "key_path",
        [
            ["Traditional_OpenSSL_Serialization", "testrsa-encrypted.pem"],
            ["PKCS8", "enc-rsa-pkcs8.pem"],
        ],
    )
    def test_password_not_bytes(self, key_path, backend):
        key_file = os.path.join("asymmetric", *key_path)
        password = "this password is not bytes"

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_private_key(
                    pemfile.read().encode(),
                    password,  # type:ignore[arg-type]
                    backend,
                ),
            )

    @pytest.mark.parametrize(
        "key_path",
        [
            ["Traditional_OpenSSL_Serialization", "testrsa-encrypted.pem"],
            ["PKCS8", "enc-rsa-pkcs8.pem"],
        ],
    )
    def test_wrong_password(self, key_path, backend):
        key_file = os.path.join("asymmetric", *key_path)
        password = b"this password is wrong"

        with pytest.raises(ValueError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_private_key(
                    pemfile.read().encode(), password, backend
                ),
            )

    @pytest.mark.parametrize(
        ("key_path", "password"),
        itertools.product(
            [
                ["Traditional_OpenSSL_Serialization", "testrsa-encrypted.pem"],
                ["PKCS8", "enc-rsa-pkcs8.pem"],
            ],
            [b"", None],
        ),
    )
    def test_missing_password(self, key_path, password, backend):
        key_file = os.path.join("asymmetric", *key_path)

        with pytest.raises(TypeError):
            load_vectors_from_file(
                key_file,
                lambda pemfile: load_pem_private_key(
                    pemfile.read().encode(), password, backend
                ),
            )

    def test_wrong_private_format(self, backend):
        key_data = b"---- NOT A KEY ----\n"

        with pytest.raises(ValueError):
            load_pem_private_key(key_data, None, backend)

        with pytest.raises(ValueError):
            load_pem_private_key(
                key_data, b"this password will not be used", backend
            )

    def test_wrong_public_format(self, backend):
        key_data = b"---- NOT A KEY ----\n"

        with pytest.raises(ValueError):
            load_pem_public_key(key_data, backend)

    @pytest.mark.supported(
        only_if=lambda backend: backend.dh_supported(),
        skip_message="DH not supported",
    )
    def test_wrong_parameters_format(self, backend):
        param_data = b"---- NOT A KEY ----\n"

        with pytest.raises(ValueError):
            load_pem_parameters(param_data, backend)

    def test_corrupt_traditional_format(self, backend):
        # privkey.pem with a bunch of data missing.
        key_data = textwrap.dedent(
            """\
        -----BEGIN RSA PRIVATE KEY-----
        MIIBPAIBAAJBAKrbeqkuRk8VcRmWFmtP+LviMB3+6dizWW3DwaffznyHGAFwUJ/I
        Tv0XtbsCyl3QoyKGhrOAy3RvPK5M38iuXT0CAwEAAQJAZ3cnzaHXM/bxGaR5CR1R
        rD1qFBAVfoQFiOH9uPJgMaoAuoQEisPHVcZDKcOv4wEg6/TInAIXBnEigtqvRzuy
        mvcpHZwQJdmdHHkGKAs37Dfxi67HbkUCIQCeZGliHXFa071Fp06ZeWlR2ADonTZz
        rJBhdTe0v5pCeQIhAIZfkiGgGBX4cIuuckzEm43g9WMUjxP/0GlK39vIyihxAiEA
        mymehFRT0MvqW5xAKAx7Pgkt8HVKwVhc2LwGKHE0DZM=
        -----END RSA PRIVATE KEY-----
        """
        ).encode()

        with pytest.raises(ValueError):
            load_pem_private_key(key_data, None, backend)

        with pytest.raises(ValueError):
            load_pem_private_key(
                key_data, b"this password will not be used", backend
            )

    def test_traditional_encrypted_corrupt_format(self, backend):
        # privkey.pem with a single bit flipped
        key_data = textwrap.dedent(
            """\
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
        """
        ).encode()

        password = b"this password is wrong"

        with pytest.raises(ValueError):
            load_pem_private_key(key_data, None, backend)

        with pytest.raises(ValueError):
            load_pem_private_key(key_data, password, backend)

    def test_unsupported_key_encryption(self, backend):
        key_data = textwrap.dedent(
            """\
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
        """
        ).encode()

        password = b"password"

        with pytest.raises(ValueError):
            load_pem_private_key(key_data, password, backend)

    def test_corrupt_pkcs8_format(self, backend):
        # unenc-rsa-pkcs8.pem with a bunch of data missing.
        key_data = textwrap.dedent(
            """\
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
        """
        ).encode()

        with pytest.raises(ValueError):
            load_pem_private_key(key_data, None, backend)

        with pytest.raises(ValueError):
            load_pem_private_key(
                key_data, b"this password will not be used", backend
            )

    def test_pks8_encrypted_corrupt_format(self, backend):
        # enc-rsa-pkcs8.pem with some bits flipped.
        key_data = textwrap.dedent(
            """\
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
        """
        ).encode()

        password = b"this password is wrong"

        with pytest.raises(ValueError):
            load_pem_private_key(key_data, None, backend)

        with pytest.raises(ValueError):
            load_pem_private_key(key_data, password, backend)

    @pytest.mark.skip_fips(reason="non-FIPS parameters")
    def test_rsa_pkcs8_encrypted_values(self, backend):
        pkey = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "enc-rsa-pkcs8.pem"),
            lambda pemfile: load_pem_private_key(
                pemfile.read().encode(),
                b"foobar",
                unsafe_skip_rsa_key_validation=True,
            ),
        )
        assert isinstance(pkey, rsa.RSAPrivateKey)

        numbers = pkey.private_numbers()

        assert numbers.public_numbers.n == int(
            "00beec64d6db5760ac2fd4c971145641b9bd7f5c56558ece608795c79807"
            "376a7fe5b19f95b35ca358ea5c8abd7ae051d49cd2f1e45969a1ae945460"
            "3c14b278664a0e414ebc8913acb6203626985525e17a600611b028542dd0"
            "562aad787fb4f1650aa318cdcff751e1b187cbf6785fbe164e9809491b95"
            "dd68480567c99b1a57",
            16,
        )

        assert numbers.public_numbers.e == 65537

        assert numbers.d == int(
            "0cfe316e9dc6b8817f4fcfd5ae38a0886f68f773b8a6db4c9e6d8703c599"
            "f3d9785c3a2c09e4c8090909fb3721e19a3009ec21221523a729265707a5"
            "8f13063671c42a4096cad378ef2510cb59e23071489d8893ac4934dd149f"
            "34f2d094bea57f1c8027c3a77248ac9b91218737d0c3c3dfa7d7829e6977"
            "cf7d995688c86c81",
            16,
        )

        assert numbers.p == int(
            "00db122ac857b2c0437d7616daa98e597bb75ca9ad3a47a70bec10c10036"
            "03328794b225c8e3eee6ffd3fd6d2253d28e071fe27d629ab072faa14377"
            "ce6118cb67",
            16,
        )

        assert numbers.q == int(
            "00df1b8aa8506fcbbbb9d00257f2975e38b33d2698fd0f37e82d7ef38c56"
            "f21b6ced63c825383782a7115cfcc093300987dbd2853b518d1c8f26382a"
            "2d2586d391",
            16,
        )

        assert numbers.dmp1 == int(
            "00be18aca13e60712fdf5daa85421eb10d86d654b269e1255656194fb0c4"
            "2dd01a1070ea12c19f5c39e09587af02f7b1a1030d016a9ffabf3b36d699"
            "ceaf38d9bf",
            16,
        )

        assert numbers.dmq1 == int(
            "71aa8978f90a0c050744b77cf1263725b203ac9f730606d8ae1d289dce4a"
            "28b8d534e9ea347aeb808c73107e583eb80c546d2bddadcdb3c82693a4c1"
            "3d863451",
            16,
        )

        assert numbers.iqmp == int(
            "136b7b1afac6e6279f71b24217b7083485a5e827d156024609dae39d48a6"
            "bdb55af2f062cc4a3b077434e6fffad5faa29a2b5dba2bed3e4621e478c0"
            "97ccfe7f",
            16,
        )

    @pytest.mark.supported(
        only_if=lambda backend: backend.dsa_supported(),
        skip_message="Does not support DSA.",
    )
    def test_load_pem_dsa_private_key(self, backend):
        key = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "unenc-dsa-pkcs8.pem"),
            lambda pemfile: load_pem_private_key(
                pemfile.read().encode(), None, backend
            ),
        )
        assert key
        assert isinstance(key, dsa.DSAPrivateKey)

        params = key.parameters()
        assert isinstance(params, dsa.DSAParameters)

        num = key.private_numbers()
        pub = num.public_numbers
        parameter_numbers = pub.parameter_numbers
        assert num.x == int("00a535a8e1d0d91beafc8bee1d9b2a3a8de3311203", 16)
        assert pub.y == int(
            "2b260ea97dc6a12ae932c640e7df3d8ff04a8a05a0324f8d5f1b23f15fa1"
            "70ff3f42061124eff2586cb11b49a82dcdc1b90fc6a84fb10109cb67db5d"
            "2da971aeaf17be5e37284563e4c64d9e5fc8480258b319f0de29d54d8350"
            "70d9e287914d77df81491f4423b62da984eb3f45eb2a29fcea5dae525ac6"
            "ab6bcce04bfdf5b6",
            16,
        )

        assert parameter_numbers.p == int(
            "00aa0930cc145825221caffa28ac2894196a27833de5ec21270791689420"
            "7774a2e7b238b0d36f1b2499a2c2585083eb01432924418d867faa212dd1"
            "071d4dceb2782794ad393cc08a4d4ada7f68d6e839a5fcd34b4e402d82cb"
            "8a8cb40fec31911bf9bd360b034caacb4c5e947992573c9e90099c1b0f05"
            "940cabe5d2de49a167",
            16,
        )

        assert parameter_numbers.q == int(
            "00adc0e869b36f0ac013a681fdf4d4899d69820451", 16
        )

        assert parameter_numbers.g == int(
            "008c6b4589afa53a4d1048bfc346d1f386ca75521ccf72ddaa251286880e"
            "e13201ff48890bbfc33d79bacaec71e7a778507bd5f1a66422e39415be03"
            "e71141ba324f5b93131929182c88a9fa4062836066cebe74b5c6690c7d10"
            "1106c240ab7ebd54e4e3301fd086ce6adac922fb2713a2b0887cba13b9bc"
            "68ce5cfff241cd3246",
            16,
        )

    @pytest.mark.parametrize(
        ("key_file", "password"), [("bad-oid-dsa-key.pem", None)]
    )
    def test_load_bad_oid_key(self, key_file, password, backend):
        with pytest.raises(ValueError):
            load_vectors_from_file(
                os.path.join("asymmetric", "PKCS8", key_file),
                lambda pemfile: load_pem_private_key(
                    pemfile.read().encode(), password, backend
                ),
            )

    @pytest.mark.parametrize(
        ("key_file", "password"), [("bad-encryption-oid.pem", b"password")]
    )
    def test_load_bad_encryption_oid_key(self, key_file, password, backend):
        with pytest.raises(ValueError):
            load_vectors_from_file(
                os.path.join("asymmetric", "PKCS8", key_file),
                lambda pemfile: load_pem_private_key(
                    pemfile.read().encode(), password, backend
                ),
            )

    def test_encrypted_pkcs8_non_utf_password(self):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "PKCS8", "enc-rsa-pkcs8.pem"),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_pem_private_key(data, password=b"\xff")

    def test_rsa_private_key_invalid_version(self):
        data = load_vectors_from_file(
            os.path.join(
                "asymmetric",
                "Traditional_OpenSSL_Serialization",
                "rsa-wrong-version.pem",
            ),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_pem_private_key(data, password=None)

    def test_dsa_private_key_invalid_version(self):
        data = load_vectors_from_file(
            os.path.join(
                "asymmetric",
                "Traditional_OpenSSL_Serialization",
                "dsa-wrong-version.pem",
            ),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_pem_private_key(data, password=None)

    def test_pem_encryption_missing_dek_info(self):
        data = load_vectors_from_file(
            os.path.join(
                "asymmetric",
                "Traditional_OpenSSL_Serialization",
                "key1-no-dek-info.pem",
            ),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_pem_private_key(data, password=b"password")

    def test_pem_encryption_malformed_dek_info(self):
        data = load_vectors_from_file(
            os.path.join(
                "asymmetric",
                "Traditional_OpenSSL_Serialization",
                "key1-malformed-dek-info.pem",
            ),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_pem_private_key(data, password=b"password")

    def test_pem_encryption_malformed_iv(self):
        data = load_vectors_from_file(
            os.path.join(
                "asymmetric",
                "Traditional_OpenSSL_Serialization",
                "key1-malformed-iv.pem",
            ),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_pem_private_key(data, password=b"password")

    def test_pem_encryption_short_iv(self):
        data = load_vectors_from_file(
            os.path.join(
                "asymmetric",
                "Traditional_OpenSSL_Serialization",
                "key1-short-iv.pem",
            ),
            lambda f: f.read(),
            mode="rb",
        )
        with pytest.raises(ValueError):
            load_pem_private_key(data, password=b"password")


class TestKeySerializationEncryptionTypes:
    def test_non_bytes_password(self):
        with pytest.raises(ValueError):
            BestAvailableEncryption(object())  # type:ignore[arg-type]

    def test_encryption_with_zero_length_password(self):
        with pytest.raises(ValueError):
            BestAvailableEncryption(b"")


@pytest.mark.supported(
    only_if=lambda backend: backend.ed25519_supported(),
    skip_message="Requires OpenSSL with Ed25519 support",
)
class TestEd25519Serialization:
    def test_load_der_private_key(self, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "Ed25519", "ed25519-pkcs8-enc.der"),
            lambda derfile: derfile.read(),
            mode="rb",
        )
        unencrypted = load_vectors_from_file(
            os.path.join("asymmetric", "Ed25519", "ed25519-pkcs8.der"),
            lambda derfile: derfile.read(),
            mode="rb",
        )
        key = load_der_private_key(data, b"password", backend)
        assert (
            key.private_bytes(
                Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
            )
            == unencrypted
        )

    def test_load_pem_private_key(self, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "Ed25519", "ed25519-pkcs8-enc.pem"),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        unencrypted = load_vectors_from_file(
            os.path.join("asymmetric", "Ed25519", "ed25519-pkcs8.pem"),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        key = load_pem_private_key(data, b"password", backend)
        assert (
            key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
            == unencrypted
        )

    @pytest.mark.parametrize(
        ("key_path", "encoding", "loader"),
        [
            (
                ["Ed25519", "ed25519-pub.pem"],
                Encoding.PEM,
                load_pem_public_key,
            ),
            (
                ["Ed25519", "ed25519-pub.der"],
                Encoding.DER,
                load_der_public_key,
            ),
        ],
    )
    def test_load_public_key(self, key_path, encoding, loader, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        public_key = loader(data, backend)
        assert (
            public_key.public_bytes(
                encoding, PublicFormat.SubjectPublicKeyInfo
            )
            == data
        )

    def test_openssl_serialization_unsupported(self, backend):
        key = ed25519.Ed25519PrivateKey.generate()
        with pytest.raises(ValueError):
            key.private_bytes(
                Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption(),
            )
        with pytest.raises(ValueError):
            key.private_bytes(
                Encoding.DER,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption(),
            )


@pytest.mark.supported(
    only_if=lambda backend: backend.x448_supported(),
    skip_message="Requires OpenSSL with X448 support",
)
class TestX448Serialization:
    def test_load_der_private_key(self, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "X448", "x448-pkcs8-enc.der"),
            lambda derfile: derfile.read(),
            mode="rb",
        )
        unencrypted = load_vectors_from_file(
            os.path.join("asymmetric", "X448", "x448-pkcs8.der"),
            lambda derfile: derfile.read(),
            mode="rb",
        )
        key = load_der_private_key(data, b"password", backend)
        assert (
            key.private_bytes(
                Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
            )
            == unencrypted
        )

    def test_load_pem_private_key(self, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "X448", "x448-pkcs8-enc.pem"),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        unencrypted = load_vectors_from_file(
            os.path.join("asymmetric", "X448", "x448-pkcs8.pem"),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        key = load_pem_private_key(data, b"password", backend)
        assert (
            key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
            == unencrypted
        )

    @pytest.mark.parametrize(
        ("key_path", "encoding", "loader"),
        [
            (["X448", "x448-pub.pem"], Encoding.PEM, load_pem_public_key),
            (["X448", "x448-pub.der"], Encoding.DER, load_der_public_key),
        ],
    )
    def test_load_public_key(self, key_path, encoding, loader, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        public_key = loader(data, backend)
        assert (
            public_key.public_bytes(
                encoding, PublicFormat.SubjectPublicKeyInfo
            )
            == data
        )

    def test_openssl_serialization_unsupported(self, backend):
        key = x448.X448PrivateKey.generate()
        with pytest.raises(ValueError):
            key.private_bytes(
                Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption(),
            )
        with pytest.raises(ValueError):
            key.private_bytes(
                Encoding.DER,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption(),
            )

    def test_openssh_serialization_unsupported(self, backend):
        key = x448.X448PrivateKey.generate()
        with pytest.raises(ValueError):
            key.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            )
        with pytest.raises(ValueError):
            key.private_bytes(
                Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
            )


@pytest.mark.supported(
    only_if=lambda backend: backend.x25519_supported(),
    skip_message="Requires OpenSSL with X25519 support",
)
class TestX25519Serialization:
    def test_load_der_private_key(self, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "X25519", "x25519-pkcs8-enc.der"),
            lambda derfile: derfile.read(),
            mode="rb",
        )
        unencrypted = load_vectors_from_file(
            os.path.join("asymmetric", "X25519", "x25519-pkcs8.der"),
            lambda derfile: derfile.read(),
            mode="rb",
        )
        key = load_der_private_key(data, b"password", backend)
        assert (
            key.private_bytes(
                Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
            )
            == unencrypted
        )

    def test_load_pem_private_key(self, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "X25519", "x25519-pkcs8-enc.pem"),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        unencrypted = load_vectors_from_file(
            os.path.join("asymmetric", "X25519", "x25519-pkcs8.pem"),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        key = load_pem_private_key(data, b"password", backend)
        assert (
            key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
            == unencrypted
        )

    @pytest.mark.parametrize(
        ("key_path", "encoding", "loader"),
        [
            (["X25519", "x25519-pub.pem"], Encoding.PEM, load_pem_public_key),
            (["X25519", "x25519-pub.der"], Encoding.DER, load_der_public_key),
        ],
    )
    def test_load_public_key(self, key_path, encoding, loader, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        public_key = loader(data, backend)
        assert (
            public_key.public_bytes(
                encoding, PublicFormat.SubjectPublicKeyInfo
            )
            == data
        )

    def test_openssl_serialization_unsupported(self, backend):
        key = x25519.X25519PrivateKey.generate()
        with pytest.raises(ValueError):
            key.private_bytes(
                Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption(),
            )
        with pytest.raises(ValueError):
            key.private_bytes(
                Encoding.DER,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption(),
            )

    def test_openssh_serialization_unsupported(self, backend):
        key = x25519.X25519PrivateKey.generate()
        with pytest.raises(ValueError):
            key.public_key().public_bytes(
                Encoding.OpenSSH, PublicFormat.OpenSSH
            )
        with pytest.raises(ValueError):
            key.private_bytes(
                Encoding.PEM, PrivateFormat.OpenSSH, NoEncryption()
            )


@pytest.mark.supported(
    only_if=lambda backend: backend.ed448_supported(),
    skip_message="Requires OpenSSL with Ed448 support",
)
class TestEd448Serialization:
    def test_load_der_private_key(self, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "Ed448", "ed448-pkcs8-enc.der"),
            lambda derfile: derfile.read(),
            mode="rb",
        )
        unencrypted = load_vectors_from_file(
            os.path.join("asymmetric", "Ed448", "ed448-pkcs8.der"),
            lambda derfile: derfile.read(),
            mode="rb",
        )
        key = load_der_private_key(data, b"password", backend)
        assert (
            key.private_bytes(
                Encoding.DER, PrivateFormat.PKCS8, NoEncryption()
            )
            == unencrypted
        )

    def test_load_pem_private_key(self, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "Ed448", "ed448-pkcs8-enc.pem"),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        unencrypted = load_vectors_from_file(
            os.path.join("asymmetric", "Ed448", "ed448-pkcs8.pem"),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        key = load_pem_private_key(data, b"password", backend)
        assert (
            key.private_bytes(
                Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
            )
            == unencrypted
        )

    @pytest.mark.parametrize(
        ("key_path", "encoding", "loader"),
        [
            (["Ed448", "ed448-pub.pem"], Encoding.PEM, load_pem_public_key),
            (["Ed448", "ed448-pub.der"], Encoding.DER, load_der_public_key),
        ],
    )
    def test_load_public_key(self, key_path, encoding, loader, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", *key_path),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        public_key = loader(data, backend)
        assert (
            public_key.public_bytes(
                encoding, PublicFormat.SubjectPublicKeyInfo
            )
            == data
        )

    def test_openssl_serialization_unsupported(self, backend):
        key = ed448.Ed448PrivateKey.generate()
        with pytest.raises(ValueError):
            key.private_bytes(
                Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption(),
            )
        with pytest.raises(ValueError):
            key.private_bytes(
                Encoding.DER,
                PrivateFormat.TraditionalOpenSSL,
                NoEncryption(),
            )

    def test_openssh_serialization_unsupported(self, backend):
        key = ed448.Ed448PrivateKey.generate()
        with pytest.raises(ValueError):
            key.public_key().public_bytes(
                Encoding.OpenSSH,
                PublicFormat.OpenSSH,
            )
        with pytest.raises(ValueError):
            key.private_bytes(
                Encoding.PEM,
                PrivateFormat.OpenSSH,
                NoEncryption(),
            )


@pytest.mark.supported(
    only_if=lambda backend: backend.dh_supported(),
    skip_message="DH not supported",
)
class TestDHSerialization:
    """Test all options with least-supported key type."""

    @pytest.mark.skip_fips(reason="non-FIPS parameters")
    def test_dh_public_key(self, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "DH", "dhkey.pem"),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        public_key = load_pem_private_key(data, None, backend).public_key()
        for enc in (
            Encoding.PEM,
            Encoding.DER,
            Encoding.OpenSSH,
            Encoding.Raw,
            Encoding.X962,
        ):
            for fmt in (
                PublicFormat.SubjectPublicKeyInfo,
                PublicFormat.PKCS1,
                PublicFormat.OpenSSH,
                PublicFormat.Raw,
                PublicFormat.CompressedPoint,
                PublicFormat.UncompressedPoint,
            ):
                if (
                    enc in (Encoding.PEM, Encoding.DER)
                    and fmt == PublicFormat.SubjectPublicKeyInfo
                ):
                    # tested elsewhere
                    continue
                with pytest.raises(ValueError):
                    public_key.public_bytes(enc, fmt)

    @pytest.mark.skip_fips(reason="non-FIPS parameters")
    def test_dh_private_key(self, backend):
        data = load_vectors_from_file(
            os.path.join("asymmetric", "DH", "dhkey.pem"),
            lambda pemfile: pemfile.read(),
            mode="rb",
        )
        private_key = load_pem_private_key(data, None, backend)
        for enc in (
            Encoding.PEM,
            Encoding.DER,
            Encoding.OpenSSH,
            Encoding.Raw,
            Encoding.X962,
        ):
            for fmt in (
                PrivateFormat.PKCS8,
                PrivateFormat.TraditionalOpenSSL,
                PrivateFormat.Raw,
            ):
                if (
                    enc in (Encoding.PEM, Encoding.DER)
                    and fmt is PrivateFormat.PKCS8
                ):
                    # tested elsewhere
                    continue
                with pytest.raises(ValueError):
                    private_key.private_bytes(enc, fmt, NoEncryption())


class TestEncryptionBuilder:
    def test_unsupported_format(self):
        f = PrivateFormat.PKCS8
        with pytest.raises(ValueError):
            f.encryption_builder()

    def test_duplicate_kdf_rounds(self):
        b = PrivateFormat.OpenSSH.encryption_builder().kdf_rounds(12)
        with pytest.raises(ValueError):
            b.kdf_rounds(12)

    def test_invalid_kdf_rounds(self):
        b = PrivateFormat.OpenSSH.encryption_builder()
        with pytest.raises(ValueError):
            b.kdf_rounds(0)
        with pytest.raises(ValueError):
            b.kdf_rounds(-1)
        with pytest.raises(TypeError):
            b.kdf_rounds("string")  # type: ignore[arg-type]

    def test_invalid_password(self):
        b = PrivateFormat.OpenSSH.encryption_builder()
        with pytest.raises(ValueError):
            b.build(12)  # type: ignore[arg-type]
        with pytest.raises(ValueError):
            b.build(b"")

    def test_unsupported_type_for_methods(self):
        b = PrivateFormat.OpenSSH.encryption_builder()
        with pytest.raises(TypeError):
            b.key_cert_algorithm(PBES.PBESv1SHA1And3KeyTripleDESCBC)
        with pytest.raises(TypeError):
            b.hmac_hash(SHA1())

    def test_duplicate_hmac_hash(self):
        b = PrivateFormat.PKCS12.encryption_builder().hmac_hash(SHA1())
        with pytest.raises(ValueError):
            b.hmac_hash(SHA1())

    def test_duplicate_key_cert_algorithm(self):
        b = PrivateFormat.PKCS12.encryption_builder().key_cert_algorithm(
            PBES.PBESv1SHA1And3KeyTripleDESCBC
        )
        with pytest.raises(ValueError):
            b.key_cert_algorithm(PBES.PBESv1SHA1And3KeyTripleDESCBC)
