# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

import pytest

from cryptography import x509
from cryptography.hazmat.backends.interfaces import DERSerializationBackend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    load_key_and_certificates
)

from .utils import load_vectors_from_file


@pytest.mark.requires_backend_interface(interface=DERSerializationBackend)
class TestPKCS12(object):
    @pytest.mark.parametrize(
        ("filename", "password"),
        [
            ("cert-key-aes256cbc.p12", b"cryptography"),
            ("cert-none-key-none.p12", b"cryptography"),
            ("cert-rc2-key-3des.p12", b"cryptography"),
            ("no-password.p12", None),
        ]
    )
    def test_load_pkcs12_ec_keys(self, filename, password, backend):
        cert = load_vectors_from_file(
            os.path.join("x509", "custom", "ca", "ca.pem"),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            ), mode="rb"
        )
        key = load_vectors_from_file(
            os.path.join("x509", "custom", "ca", "ca_key.pem"),
            lambda pemfile: load_pem_private_key(
                pemfile.read(), None, backend
            ), mode="rb"
        )
        parsed_key, parsed_cert, parsed_more_certs = load_vectors_from_file(
            os.path.join("pkcs12", filename),
            lambda derfile: load_key_and_certificates(
                derfile.read(), password, backend
            ), mode="rb"
        )
        assert parsed_cert == cert
        assert parsed_key.private_numbers() == key.private_numbers()
        assert parsed_more_certs == []

    def test_load_pkcs12_cert_only(self, backend):
        cert = load_vectors_from_file(
            os.path.join("x509", "custom", "ca", "ca.pem"),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            ), mode="rb"
        )
        parsed_key, parsed_cert, parsed_more_certs = load_vectors_from_file(
            os.path.join("pkcs12", "cert-aes256cbc-no-key.p12"),
            lambda data: load_key_and_certificates(
                data.read(), b"cryptography", backend
            ),
            mode="rb"
        )
        assert parsed_cert is None
        assert parsed_key is None
        assert parsed_more_certs == [cert]

    def test_load_pkcs12_key_only(self, backend):
        key = load_vectors_from_file(
            os.path.join("x509", "custom", "ca", "ca_key.pem"),
            lambda pemfile: load_pem_private_key(
                pemfile.read(), None, backend
            ), mode="rb"
        )
        parsed_key, parsed_cert, parsed_more_certs = load_vectors_from_file(
            os.path.join("pkcs12", "no-cert-key-aes256cbc.p12"),
            lambda data: load_key_and_certificates(
                data.read(), b"cryptography", backend
            ),
            mode="rb"
        )
        assert parsed_key.private_numbers() == key.private_numbers()
        assert parsed_cert is None
        assert parsed_more_certs == []

    def test_non_bytes(self, backend):
        with pytest.raises(TypeError):
            load_key_and_certificates(
                b"irrelevant", object(), backend
            )

    def test_not_a_pkcs12(self, backend):
        with pytest.raises(ValueError):
            load_key_and_certificates(
                b"invalid", b"pass", backend
            )

    def test_invalid_password(self, backend):
        with pytest.raises(ValueError):
            load_vectors_from_file(
                os.path.join("pkcs12", "cert-key-aes256cbc.p12"),
                lambda derfile: load_key_and_certificates(
                    derfile.read(), b"invalid", backend
                ), mode="rb"
            )

    def test_buffer_protocol(self, backend):
        p12 = load_vectors_from_file(
            os.path.join("pkcs12", "cert-key-aes256cbc.p12"),
            lambda derfile: derfile.read(), mode="rb"
        )
        p12buffer = bytearray(p12)
        parsed_key, parsed_cert, parsed_more_certs = load_key_and_certificates(
            p12buffer, bytearray(b"cryptography"), backend
        )
        assert parsed_key is not None
        assert parsed_cert is not None
        assert parsed_more_certs == []
