# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import os
from datetime import datetime

import pytest

from cryptography import x509
from cryptography.hazmat.backends.openssl.backend import _RC2
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates,
    serialize_key_and_certificates,
)

from .utils import load_vectors_from_file
from ...doubles import DummyKeySerializationEncryption


class TestPKCS12Loading(object):
    def _test_load_pkcs12_ec_keys(self, filename, password, backend):
        cert = load_vectors_from_file(
            os.path.join("x509", "custom", "ca", "ca.pem"),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            ),
            mode="rb",
        )
        key = load_vectors_from_file(
            os.path.join("x509", "custom", "ca", "ca_key.pem"),
            lambda pemfile: load_pem_private_key(
                pemfile.read(), None, backend
            ),
            mode="rb",
        )
        parsed_key, parsed_cert, parsed_more_certs = load_vectors_from_file(
            os.path.join("pkcs12", filename),
            lambda derfile: load_key_and_certificates(
                derfile.read(), password, backend
            ),
            mode="rb",
        )
        assert parsed_cert == cert
        assert parsed_key.private_numbers() == key.private_numbers()
        assert parsed_more_certs == []

    @pytest.mark.parametrize(
        ("filename", "password"),
        [
            ("cert-key-aes256cbc.p12", b"cryptography"),
            ("cert-none-key-none.p12", b"cryptography"),
        ],
    )
    def test_load_pkcs12_ec_keys(self, filename, password, backend):
        self._test_load_pkcs12_ec_keys(filename, password, backend)

    @pytest.mark.parametrize(
        ("filename", "password"),
        [
            ("cert-rc2-key-3des.p12", b"cryptography"),
            ("no-password.p12", None),
        ],
    )
    @pytest.mark.supported(
        only_if=lambda backend: backend.cipher_supported(_RC2(), None),
        skip_message="Does not support RC2",
    )
    @pytest.mark.skip_fips(reason="Unsupported algorithm in FIPS mode")
    def test_load_pkcs12_ec_keys_rc2(self, filename, password, backend):
        self._test_load_pkcs12_ec_keys(filename, password, backend)

    def test_load_pkcs12_cert_only(self, backend):
        cert = load_vectors_from_file(
            os.path.join("x509", "custom", "ca", "ca.pem"),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            ),
            mode="rb",
        )
        parsed_key, parsed_cert, parsed_more_certs = load_vectors_from_file(
            os.path.join("pkcs12", "cert-aes256cbc-no-key.p12"),
            lambda data: load_key_and_certificates(
                data.read(), b"cryptography", backend
            ),
            mode="rb",
        )
        assert parsed_cert is None
        assert parsed_key is None
        assert parsed_more_certs == [cert]

    def test_load_pkcs12_key_only(self, backend):
        key = load_vectors_from_file(
            os.path.join("x509", "custom", "ca", "ca_key.pem"),
            lambda pemfile: load_pem_private_key(
                pemfile.read(), None, backend
            ),
            mode="rb",
        )
        parsed_key, parsed_cert, parsed_more_certs = load_vectors_from_file(
            os.path.join("pkcs12", "no-cert-key-aes256cbc.p12"),
            lambda data: load_key_and_certificates(
                data.read(), b"cryptography", backend
            ),
            mode="rb",
        )
        assert parsed_key.private_numbers() == key.private_numbers()
        assert parsed_cert is None
        assert parsed_more_certs == []

    def test_non_bytes(self, backend):
        with pytest.raises(TypeError):
            load_key_and_certificates(
                b"irrelevant", object(), backend  # type: ignore[arg-type]
            )

    def test_not_a_pkcs12(self, backend):
        with pytest.raises(ValueError):
            load_key_and_certificates(b"invalid", b"pass", backend)

    def test_invalid_password(self, backend):
        with pytest.raises(ValueError):
            load_vectors_from_file(
                os.path.join("pkcs12", "cert-key-aes256cbc.p12"),
                lambda derfile: load_key_and_certificates(
                    derfile.read(), b"invalid", backend
                ),
                mode="rb",
            )

    def test_buffer_protocol(self, backend):
        p12 = load_vectors_from_file(
            os.path.join("pkcs12", "cert-key-aes256cbc.p12"),
            lambda derfile: derfile.read(),
            mode="rb",
        )
        p12buffer = bytearray(p12)
        parsed_key, parsed_cert, parsed_more_certs = load_key_and_certificates(
            p12buffer, bytearray(b"cryptography"), backend
        )
        assert parsed_key is not None
        assert parsed_cert is not None
        assert parsed_more_certs == []


def _load_cert(backend, path):
    return load_vectors_from_file(
        path,
        lambda pemfile: x509.load_pem_x509_certificate(
            pemfile.read(), backend
        ),
        mode="rb",
    )


def _load_ca(backend):
    cert = _load_cert(backend, os.path.join("x509", "custom", "ca", "ca.pem"))
    key = load_vectors_from_file(
        os.path.join("x509", "custom", "ca", "ca_key.pem"),
        lambda pemfile: load_pem_private_key(pemfile.read(), None, backend),
        mode="rb",
    )
    return cert, key


class TestPKCS12Creation(object):
    @pytest.mark.parametrize("name", [None, b"name"])
    @pytest.mark.parametrize(
        ("encryption_algorithm", "password"),
        [
            (serialization.BestAvailableEncryption(b"password"), b"password"),
            (serialization.NoEncryption(), None),
        ],
    )
    def test_generate(self, backend, name, encryption_algorithm, password):
        cert, key = _load_ca(backend)
        p12 = serialize_key_and_certificates(
            name, key, cert, None, encryption_algorithm
        )

        parsed_key, parsed_cert, parsed_more_certs = load_key_and_certificates(
            p12, password, backend
        )
        assert parsed_cert == cert
        assert parsed_key is not None
        assert parsed_key.private_numbers() == key.private_numbers()
        assert parsed_more_certs == []

    def test_generate_with_cert_key_ca(self, backend):
        cert, key = _load_ca(backend)
        cert2 = _load_cert(
            backend, os.path.join("x509", "custom", "dsa_selfsigned_ca.pem")
        )
        cert3 = _load_cert(backend, os.path.join("x509", "letsencryptx3.pem"))
        encryption = serialization.NoEncryption()
        p12 = serialize_key_and_certificates(
            None, key, cert, [cert2, cert3], encryption
        )

        parsed_key, parsed_cert, parsed_more_certs = load_key_and_certificates(
            p12, None, backend
        )
        assert parsed_cert == cert
        assert parsed_key is not None
        assert parsed_key.private_numbers() == key.private_numbers()
        assert parsed_more_certs == [cert2, cert3]

    def test_generate_wrong_types(self, backend):
        cert, key = _load_ca(backend)
        cert2 = _load_cert(backend, os.path.join("x509", "letsencryptx3.pem"))
        encryption = serialization.NoEncryption()
        with pytest.raises(TypeError) as exc:
            serialize_key_and_certificates(
                b"name", cert, cert, None, encryption
            )
        assert (
            str(exc.value)
            == "Key must be RSA, DSA, or EllipticCurve private key."
        )

        with pytest.raises(TypeError) as exc:
            serialize_key_and_certificates(b"name", key, key, None, encryption)
        assert str(exc.value) == "cert must be a certificate"

        with pytest.raises(TypeError) as exc:
            serialize_key_and_certificates(b"name", key, cert, None, key)
        assert str(exc.value) == (
            "Key encryption algorithm must be a "
            "KeySerializationEncryption instance"
        )

        with pytest.raises(TypeError) as exc:
            serialize_key_and_certificates(None, key, cert, cert2, encryption)

        with pytest.raises(TypeError) as exc:
            serialize_key_and_certificates(None, key, cert, [key], encryption)
        assert str(exc.value) == "all values in cas must be certificates"

    def test_generate_no_cert(self, backend):
        _, key = _load_ca(backend)
        p12 = serialize_key_and_certificates(
            None, key, None, None, serialization.NoEncryption()
        )
        parsed_key, parsed_cert, parsed_more_certs = load_key_and_certificates(
            p12, None, backend
        )
        assert parsed_cert is None
        assert parsed_key is not None
        assert parsed_key.private_numbers() == key.private_numbers()
        assert parsed_more_certs == []

    def test_must_supply_something(self):
        with pytest.raises(ValueError) as exc:
            serialize_key_and_certificates(
                None, None, None, None, serialization.NoEncryption()
            )
        assert str(exc.value) == (
            "You must supply at least one of key, cert, or cas"
        )

    def test_generate_unsupported_encryption_type(self, backend):
        cert, key = _load_ca(backend)
        with pytest.raises(ValueError) as exc:
            serialize_key_and_certificates(
                None,
                key,
                cert,
                None,
                DummyKeySerializationEncryption(),
            )
        assert str(exc.value) == "Unsupported key encryption type"


def test_pkcs12_ordering():
    """
    In OpenSSL < 3.0.0 PKCS12 parsing reverses the order. However, we
    accidentally thought it was **encoding** that did it, leading to bug
    https://github.com/pyca/cryptography/issues/5872
    This test ensures our ordering is correct going forward.
    """

    def make_cert(name):
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, name),
            ]
        )
        now = datetime.utcnow()
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now)
            .sign(key, hashes.SHA256())
        )
        return (key, cert)

    # Make some certificates with distinct names.
    a_name = "A" * 20
    b_name = "B" * 20
    c_name = "C" * 20
    a_key, a_cert = make_cert(a_name)
    _, b_cert = make_cert(b_name)
    _, c_cert = make_cert(c_name)

    # Bundle them in a PKCS#12 file in order A, B, C.
    p12 = serialize_key_and_certificates(
        b"p12", a_key, a_cert, [b_cert, c_cert], serialization.NoEncryption()
    )

    # Parse them out. The API should report them in the same order.
    (key, cert, certs) = load_key_and_certificates(p12, None)
    assert cert == a_cert
    assert certs == [b_cert, c_cert]

    # The ordering in the PKCS#12 file itself should also match.
    a_idx = p12.index(a_name.encode("utf-8"))
    b_idx = p12.index(b_name.encode("utf-8"))
    c_idx = p12.index(c_name.encode("utf-8"))

    assert a_idx < b_idx < c_idx
