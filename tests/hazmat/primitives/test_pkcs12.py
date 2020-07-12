# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

import pytest

from cryptography import x509
from cryptography.hazmat.backends.interfaces import DERSerializationBackend
from cryptography.hazmat.backends.openssl.backend import _RC2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization.pkcs12 import (
    generate_pkcs12, load_key_and_certificates
)

from .utils import load_vectors_from_file
from ...doubles import DummyKeySerializationEncryption


@pytest.mark.requires_backend_interface(interface=DERSerializationBackend)
class TestPKCS12(object):
    def _test_load_pkcs12_ec_keys(self, filename, password, backend):
        cert = load_vectors_from_file(
            os.path.join('x509', 'custom', 'ca', 'ca.pem'),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            ), mode='rb'
        )
        key = load_vectors_from_file(
            os.path.join('x509', 'custom', 'ca', 'ca_key.pem'),
            lambda pemfile: load_pem_private_key(
                pemfile.read(), None, backend
            ), mode='rb'
        )
        parsed_key, parsed_cert, parsed_more_certs = load_vectors_from_file(
            os.path.join('pkcs12', filename),
            lambda derfile: load_key_and_certificates(
                derfile.read(), password, backend
            ), mode='rb'
        )
        assert parsed_cert == cert
        assert parsed_key.private_numbers() == key.private_numbers()
        assert parsed_more_certs == []

    @pytest.mark.parametrize(
        ('filename', 'password'),
        [
            ('cert-key-aes256cbc.p12', b'cryptography'),
            ('cert-none-key-none.p12', b'cryptography'),
        ]
    )
    def test_load_pkcs12_ec_keys(self, filename, password, backend):
        self._test_load_pkcs12_ec_keys(filename, password, backend)

    @pytest.mark.parametrize(
        ('filename', 'password'),
        [
            ('cert-rc2-key-3des.p12', b'cryptography'),
            ('no-password.p12', None),
        ]
    )
    @pytest.mark.supported(
        only_if=lambda backend: backend.cipher_supported(_RC2(), None),
        skip_message='Does not support RC2'
    )
    def test_load_pkcs12_ec_keys_rc2(self, filename, password, backend):
        self._test_load_pkcs12_ec_keys(filename, password, backend)

    def test_load_pkcs12_cert_only(self, backend):
        cert = load_vectors_from_file(
            os.path.join('x509', 'custom', 'ca', 'ca.pem'),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            ), mode='rb'
        )
        parsed_key, parsed_cert, parsed_more_certs = load_vectors_from_file(
            os.path.join('pkcs12', 'cert-aes256cbc-no-key.p12'),
            lambda data: load_key_and_certificates(
                data.read(), b'cryptography', backend
            ),
            mode='rb'
        )
        assert parsed_cert is None
        assert parsed_key is None
        assert parsed_more_certs == [cert]

    def test_load_pkcs12_key_only(self, backend):
        key = load_vectors_from_file(
            os.path.join('x509', 'custom', 'ca', 'ca_key.pem'),
            lambda pemfile: load_pem_private_key(
                pemfile.read(), None, backend
            ), mode='rb'
        )
        parsed_key, parsed_cert, parsed_more_certs = load_vectors_from_file(
            os.path.join('pkcs12', 'no-cert-key-aes256cbc.p12'),
            lambda data: load_key_and_certificates(
                data.read(), b'cryptography', backend
            ),
            mode='rb'
        )
        assert parsed_key.private_numbers() == key.private_numbers()
        assert parsed_cert is None
        assert parsed_more_certs == []

    def test_non_bytes(self, backend):
        with pytest.raises(TypeError):
            load_key_and_certificates(
                b'irrelevant', object(), backend
            )

    def test_not_a_pkcs12(self, backend):
        with pytest.raises(ValueError):
            load_key_and_certificates(
                b'invalid', b'pass', backend
            )

    def test_invalid_password(self, backend):
        with pytest.raises(ValueError):
            load_vectors_from_file(
                os.path.join('pkcs12', 'cert-key-aes256cbc.p12'),
                lambda derfile: load_key_and_certificates(
                    derfile.read(), b'invalid', backend
                ), mode='rb'
            )

    def test_buffer_protocol(self, backend):
        p12 = load_vectors_from_file(
            os.path.join('pkcs12', 'cert-key-aes256cbc.p12'),
            lambda derfile: derfile.read(), mode='rb'
        )
        p12buffer = bytearray(p12)
        parsed_key, parsed_cert, parsed_more_certs = load_key_and_certificates(
            p12buffer, bytearray(b'cryptography'), backend
        )
        assert parsed_key is not None
        assert parsed_cert is not None
        assert parsed_more_certs == []

    @pytest.fixture(scope='function')
    def cert(self, backend):
        return load_vectors_from_file(
            os.path.join('x509', 'custom', 'ca', 'ca.pem'),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            ), mode='rb'
        )

    @pytest.fixture(scope='function')
    def cert2(self, backend):
        return load_vectors_from_file(
            os.path.join('x509', 'custom', 'dsa_selfsigned_ca.pem'),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            ), mode='rb'
        )

    @pytest.fixture(scope='function')
    def key(self, backend):
        return load_vectors_from_file(
            os.path.join('x509', 'custom', 'ca', 'ca_key.pem'),
            lambda pemfile: load_pem_private_key(
                pemfile.read(), None, backend
            ), mode='rb'
        )

    @pytest.mark.parametrize('password', [None, b'password'])
    @pytest.mark.parametrize('name', [None, b'name'])
    @pytest.mark.parametrize('key_encryption', [
        serialization.BestAvailableEncryption(b'password'),
        serialization.NoEncryption()
    ])
    @pytest.mark.parametrize('cert_encryption', [
        serialization.BestAvailableEncryption(b'password'),
        serialization.NoEncryption()
    ])
    def test_generate(self, backend, password, name, key, cert, key_encryption,
                      cert_encryption):
        p12 = generate_pkcs12(password, name, key, cert, None, key_encryption,
                              cert_encryption)

        parsed_key, parsed_cert, parsed_more_certs = \
            load_key_and_certificates(p12, password, backend)
        assert parsed_cert == cert
        assert parsed_key.private_numbers() == key.private_numbers()
        assert parsed_more_certs == []

    def test_generate_with_ca(self, backend, key, cert, cert2):
        encryption = serialization.NoEncryption()
        p12 = generate_pkcs12(None, None, key, cert, [cert2], encryption,
                              encryption)

        parsed_key, parsed_cert, parsed_more_certs = \
            load_key_and_certificates(p12, None, backend)
        assert parsed_cert == cert
        assert parsed_key.private_numbers() == key.private_numbers()
        assert parsed_more_certs == [cert2]

        with pytest.raises(TypeError) as exc:
            generate_pkcs12(None, None, key, cert, cert2, encryption,
                            encryption)
        assert str(exc.value) == 'cas must be a list'

        with pytest.raises(TypeError) as exc:
            generate_pkcs12(None, None, key, cert, [key], encryption,
                            encryption)
        assert str(exc.value) == 'cert in cas must be a certificate'

    def test_generate_wrong_types(self, key, cert):
        encryption = serialization.NoEncryption()
        with pytest.raises(TypeError) as exc:
            generate_pkcs12(b'password', b'name', cert, cert, None,
                            encryption, encryption)
        assert str(exc.value) == \
            'Key must be RSA, DSA, or EllipticCurve private key.'

        with pytest.raises(TypeError) as exc:
            generate_pkcs12(b'password', b'name', key, key, None,
                            encryption, encryption)
        assert str(exc.value) == 'cert must be a certificate'

        with pytest.raises(TypeError) as exc:
            generate_pkcs12(b'password', b'name', key, cert, None,
                            key, encryption)
        assert str(
            exc.value) == ('Key encryption algorithm must be a '
                           'KeySerializationEncryption instance')

        with pytest.raises(TypeError) as exc:
            generate_pkcs12(b'password', b'name', key, cert, None,
                            encryption, key)
        assert str(
            exc.value) == ('Certificate encryption algorithm must be a '
                           'KeySerializationEncryption instance')

    def test_generate_no_cert(self, backend, key):
        p12 = generate_pkcs12(None, None, key, None, None,
                              serialization.NoEncryption(), None)
        parsed_key, parsed_cert, parsed_more_certs = \
            load_key_and_certificates(p12, None, backend)
        assert parsed_cert is None
        assert parsed_key.private_numbers() == key.private_numbers()
        assert parsed_more_certs == []

    def test_generate_no_cert_and_key(self):
        with pytest.raises(ValueError) as exc:
            generate_pkcs12(None, None, None, None, None,
                            serialization.NoEncryption(), None)
        assert str(exc.value) == 'Could not deserialize PKCS12 data'

    def test_generate_unsupported_encryption_type(self, key, cert):
        with pytest.raises(ValueError) as exc:
            generate_pkcs12(None, None, key, cert, None,
                            DummyKeySerializationEncryption(),
                            serialization.NoEncryption())
        assert str(exc.value) == 'Unsupported key encryption type'
        with pytest.raises(ValueError) as exc:
            generate_pkcs12(None, None, key, cert, None,
                            serialization.NoEncryption(),
                            DummyKeySerializationEncryption())
        assert str(exc.value) == 'Unsupported certificate encryption type'

    def test_generate_no_data(self):
        with pytest.raises(ValueError) as exc:
            generate_pkcs12(None, None, None, None, None, None, None)
        assert str(exc.value) == 'Could not deserialize PKCS12 data'
