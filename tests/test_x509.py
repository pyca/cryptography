# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import datetime
import os

import pytest

import six

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.interfaces import (
    DSABackend, EllipticCurveBackend, RSABackend, X509Backend
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa

from .hazmat.primitives.fixtures_dsa import DSA_KEY_2048
from .hazmat.primitives.fixtures_rsa import RSA_KEY_2048
from .hazmat.primitives.test_ec import _skip_curve_unsupported
from .utils import load_vectors_from_file


def _load_cert(filename, loader, backend):
    cert = load_vectors_from_file(
        filename=filename,
        loader=lambda pemfile: loader(pemfile.read(), backend),
        mode="rb"
    )
    return cert


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestRSACertificate(object):
    def test_load_pem_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert isinstance(cert, x509.Certificate)
        assert cert.serial == 11559813051657483483
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1()))
        assert fingerprint == b"2b619ed04bfc9c3b08eb677d272192286a0947a8"
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA1)

    def test_load_der_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )
        assert isinstance(cert, x509.Certificate)
        assert cert.serial == 2
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1()))
        assert fingerprint == b"6f49779533d565e8b7c1062503eab41492c38e4d"
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)

    def test_issuer(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "Validpre2000UTCnotBeforeDateTest3EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )
        issuer = cert.issuer
        assert isinstance(issuer, x509.Name)
        assert list(issuer) == [
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(
                x509.OID_ORGANIZATION_NAME, u'Test Certificates 2011'
            ),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'Good CA')
        ]
        assert issuer.get_attributes_for_oid(x509.OID_COMMON_NAME) == [
            x509.NameAttribute(x509.OID_COMMON_NAME, u'Good CA')
        ]

    def test_all_issuer_name_types(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom",
                "all_supported_names.pem"
            ),
            x509.load_pem_x509_certificate,
            backend
        )
        issuer = cert.issuer

        assert isinstance(issuer, x509.Name)
        assert list(issuer) == [
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'CA'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Illinois'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Chicago'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'Zero, LLC'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'One, LLC'),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'common name 0'),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'common name 1'),
            x509.NameAttribute(x509.OID_ORGANIZATIONAL_UNIT_NAME, u'OU 0'),
            x509.NameAttribute(x509.OID_ORGANIZATIONAL_UNIT_NAME, u'OU 1'),
            x509.NameAttribute(x509.OID_DN_QUALIFIER, u'dnQualifier0'),
            x509.NameAttribute(x509.OID_DN_QUALIFIER, u'dnQualifier1'),
            x509.NameAttribute(x509.OID_SERIAL_NUMBER, u'123'),
            x509.NameAttribute(x509.OID_SERIAL_NUMBER, u'456'),
            x509.NameAttribute(x509.OID_TITLE, u'Title 0'),
            x509.NameAttribute(x509.OID_TITLE, u'Title 1'),
            x509.NameAttribute(x509.OID_SURNAME, u'Surname 0'),
            x509.NameAttribute(x509.OID_SURNAME, u'Surname 1'),
            x509.NameAttribute(x509.OID_GIVEN_NAME, u'Given Name 0'),
            x509.NameAttribute(x509.OID_GIVEN_NAME, u'Given Name 1'),
            x509.NameAttribute(x509.OID_PSEUDONYM, u'Incognito 0'),
            x509.NameAttribute(x509.OID_PSEUDONYM, u'Incognito 1'),
            x509.NameAttribute(x509.OID_GENERATION_QUALIFIER, u'Last Gen'),
            x509.NameAttribute(x509.OID_GENERATION_QUALIFIER, u'Next Gen'),
            x509.NameAttribute(x509.OID_DOMAIN_COMPONENT, u'dc0'),
            x509.NameAttribute(x509.OID_DOMAIN_COMPONENT, u'dc1'),
            x509.NameAttribute(x509.OID_EMAIL_ADDRESS, u'test0@test.local'),
            x509.NameAttribute(x509.OID_EMAIL_ADDRESS, u'test1@test.local'),
        ]

    def test_subject(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "Validpre2000UTCnotBeforeDateTest3EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )
        subject = cert.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(
                x509.OID_ORGANIZATION_NAME, u'Test Certificates 2011'
            ),
            x509.NameAttribute(
                x509.OID_COMMON_NAME,
                u'Valid pre2000 UTC notBefore Date EE Certificate Test3'
            )
        ]
        assert subject.get_attributes_for_oid(x509.OID_COMMON_NAME) == [
            x509.NameAttribute(
                x509.OID_COMMON_NAME,
                u'Valid pre2000 UTC notBefore Date EE Certificate Test3'
            )
        ]

    def test_unicode_name(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom",
                "utf8_common_name.pem"
            ),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert.subject.get_attributes_for_oid(x509.OID_COMMON_NAME) == [
            x509.NameAttribute(
                x509.OID_COMMON_NAME,
                u'We heart UTF8!\u2122'
            )
        ]
        assert cert.issuer.get_attributes_for_oid(x509.OID_COMMON_NAME) == [
            x509.NameAttribute(
                x509.OID_COMMON_NAME,
                u'We heart UTF8!\u2122'
            )
        ]

    def test_all_subject_name_types(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom",
                "all_supported_names.pem"
            ),
            x509.load_pem_x509_certificate,
            backend
        )
        subject = cert.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'AU'),
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'DE'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'California'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'New York'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'San Francisco'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Ithaca'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'Org Zero, LLC'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'Org One, LLC'),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'CN 0'),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'CN 1'),
            x509.NameAttribute(
                x509.OID_ORGANIZATIONAL_UNIT_NAME, u'Engineering 0'
            ),
            x509.NameAttribute(
                x509.OID_ORGANIZATIONAL_UNIT_NAME, u'Engineering 1'
            ),
            x509.NameAttribute(x509.OID_DN_QUALIFIER, u'qualified0'),
            x509.NameAttribute(x509.OID_DN_QUALIFIER, u'qualified1'),
            x509.NameAttribute(x509.OID_SERIAL_NUMBER, u'789'),
            x509.NameAttribute(x509.OID_SERIAL_NUMBER, u'012'),
            x509.NameAttribute(x509.OID_TITLE, u'Title IX'),
            x509.NameAttribute(x509.OID_TITLE, u'Title X'),
            x509.NameAttribute(x509.OID_SURNAME, u'Last 0'),
            x509.NameAttribute(x509.OID_SURNAME, u'Last 1'),
            x509.NameAttribute(x509.OID_GIVEN_NAME, u'First 0'),
            x509.NameAttribute(x509.OID_GIVEN_NAME, u'First 1'),
            x509.NameAttribute(x509.OID_PSEUDONYM, u'Guy Incognito 0'),
            x509.NameAttribute(x509.OID_PSEUDONYM, u'Guy Incognito 1'),
            x509.NameAttribute(x509.OID_GENERATION_QUALIFIER, u'32X'),
            x509.NameAttribute(x509.OID_GENERATION_QUALIFIER, u'Dreamcast'),
            x509.NameAttribute(x509.OID_DOMAIN_COMPONENT, u'dc2'),
            x509.NameAttribute(x509.OID_DOMAIN_COMPONENT, u'dc3'),
            x509.NameAttribute(x509.OID_EMAIL_ADDRESS, u'test2@test.local'),
            x509.NameAttribute(x509.OID_EMAIL_ADDRESS, u'test3@test.local'),
        ]

    def test_load_good_ca_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )

        assert cert.not_valid_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_valid_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.serial == 2
        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert cert.version is x509.Version.v3
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1()))
        assert fingerprint == b"6f49779533d565e8b7c1062503eab41492c38e4d"

    def test_utc_pre_2000_not_before_cert(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "Validpre2000UTCnotBeforeDateTest3EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )

        assert cert.not_valid_before == datetime.datetime(1950, 1, 1, 12, 1)

    def test_pre_2000_utc_not_after_cert(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "Invalidpre2000UTCEEnotAfterDateTest7EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )

        assert cert.not_valid_after == datetime.datetime(1999, 1, 1, 12, 1)

    def test_post_2000_utc_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert.not_valid_before == datetime.datetime(
            2014, 11, 26, 21, 41, 20
        )
        assert cert.not_valid_after == datetime.datetime(
            2014, 12, 26, 21, 41, 20
        )

    def test_generalized_time_not_before_cert(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "ValidGeneralizedTimenotBeforeDateTest4EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )
        assert cert.not_valid_before == datetime.datetime(2002, 1, 1, 12, 1)
        assert cert.not_valid_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.version is x509.Version.v3

    def test_generalized_time_not_after_cert(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "ValidGeneralizedTimenotAfterDateTest8EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )
        assert cert.not_valid_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_valid_after == datetime.datetime(2050, 1, 1, 12, 1)
        assert cert.version is x509.Version.v3

    def test_invalid_version_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "invalid_version.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        with pytest.raises(x509.InvalidVersion) as exc:
            cert.version

        assert exc.value.parsed_version == 7

    def test_eq(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        cert2 = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert == cert2

    def test_ne(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        cert2 = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "ValidGeneralizedTimenotAfterDateTest8EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )
        assert cert != cert2
        assert cert != object()

    def test_version_1_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "v1_cert.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert cert.version is x509.Version.v1

    def test_invalid_pem(self, backend):
        with pytest.raises(ValueError):
            x509.load_pem_x509_certificate(b"notacert", backend)

    def test_invalid_der(self, backend):
        with pytest.raises(ValueError):
            x509.load_der_x509_certificate(b"notacert", backend)

    def test_unsupported_signature_hash_algorithm_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "verisign_md2_root.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        with pytest.raises(UnsupportedAlgorithm):
            cert.signature_hash_algorithm

    def test_public_bytes_pem(self, backend):
        # Load an existing certificate.
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )

        # Encode it to PEM and load it back.
        cert = x509.load_pem_x509_certificate(cert.public_bytes(
            encoding=serialization.Encoding.PEM,
        ), backend)

        # We should recover what we had to start with.
        assert cert.not_valid_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_valid_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.serial == 2
        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert cert.version is x509.Version.v3
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1()))
        assert fingerprint == b"6f49779533d565e8b7c1062503eab41492c38e4d"

    def test_public_bytes_der(self, backend):
        # Load an existing certificate.
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )

        # Encode it to DER and load it back.
        cert = x509.load_der_x509_certificate(cert.public_bytes(
            encoding=serialization.Encoding.DER,
        ), backend)

        # We should recover what we had to start with.
        assert cert.not_valid_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_valid_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.serial == 2
        public_key = cert.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        assert cert.version is x509.Version.v3
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1()))
        assert fingerprint == b"6f49779533d565e8b7c1062503eab41492c38e4d"

    def test_public_bytes_invalid_encoding(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            x509.load_der_x509_certificate,
            backend
        )

        with pytest.raises(TypeError):
            cert.public_bytes('NotAnEncoding')

    @pytest.mark.parametrize(
        ("cert_path", "loader_func", "encoding"),
        [
            (
                os.path.join("x509", "v1_cert.pem"),
                x509.load_pem_x509_certificate,
                serialization.Encoding.PEM,
            ),
            (
                os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
                x509.load_der_x509_certificate,
                serialization.Encoding.DER,
            ),
        ]
    )
    def test_public_bytes_match(self, cert_path, loader_func, encoding,
                                backend):
        cert_bytes = load_vectors_from_file(
            cert_path, lambda pemfile: pemfile.read(), mode="rb"
        )
        cert = loader_func(cert_bytes, backend)
        serialized = cert.public_bytes(encoding)
        assert serialized == cert_bytes

    def test_certificate_repr(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "cryptography.io.pem"
            ),
            x509.load_pem_x509_certificate,
            backend
        )
        if six.PY3:
            assert repr(cert) == (
                "<Certificate(subject=<Name([<NameAttribute(oid=<ObjectIdentif"
                "ier(oid=2.5.4.11, name=organizationalUnitName)>, value='GT487"
                "42965')>, <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.11, "
                "name=organizationalUnitName)>, value='See www.rapidssl.com/re"
                "sources/cps (c)14')>, <NameAttribute(oid=<ObjectIdentifier(oi"
                "d=2.5.4.11, name=organizationalUnitName)>, value='Domain Cont"
                "rol Validated - RapidSSL(R)')>, <NameAttribute(oid=<ObjectIde"
                "ntifier(oid=2.5.4.3, name=commonName)>, value='www.cryptograp"
                "hy.io')>])>, ...)>"
            )
        else:
            assert repr(cert) == (
                "<Certificate(subject=<Name([<NameAttribute(oid=<ObjectIdentif"
                "ier(oid=2.5.4.11, name=organizationalUnitName)>, value=u'GT48"
                "742965')>, <NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.11,"
                " name=organizationalUnitName)>, value=u'See www.rapidssl.com/"
                "resources/cps (c)14')>, <NameAttribute(oid=<ObjectIdentifier("
                "oid=2.5.4.11, name=organizationalUnitName)>, value=u'Domain C"
                "ontrol Validated - RapidSSL(R)')>, <NameAttribute(oid=<Object"
                "Identifier(oid=2.5.4.3, name=commonName)>, value=u'www.crypto"
                "graphy.io')>])>, ...)>"
            )


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestRSACertificateRequest(object):
    @pytest.mark.parametrize(
        ("path", "loader_func"),
        [
            [
                os.path.join("x509", "requests", "rsa_sha1.pem"),
                x509.load_pem_x509_csr
            ],
            [
                os.path.join("x509", "requests", "rsa_sha1.der"),
                x509.load_der_x509_csr
            ],
        ]
    )
    def test_load_rsa_certificate_request(self, path, loader_func, backend):
        request = _load_cert(path, loader_func, backend)
        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
        ]
        extensions = request.extensions
        assert isinstance(extensions, x509.Extensions)
        assert list(extensions) == []

    @pytest.mark.parametrize(
        "loader_func",
        [x509.load_pem_x509_csr, x509.load_der_x509_csr]
    )
    def test_invalid_certificate_request(self, loader_func, backend):
        with pytest.raises(ValueError):
            loader_func(b"notacsr", backend)

    def test_unsupported_signature_hash_algorithm_request(self, backend):
        request = _load_cert(
            os.path.join("x509", "requests", "rsa_md4.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        with pytest.raises(UnsupportedAlgorithm):
            request.signature_hash_algorithm

    def test_duplicate_extension(self, backend):
        request = _load_cert(
            os.path.join(
                "x509", "requests", "two_basic_constraints.pem"
            ),
            x509.load_pem_x509_csr,
            backend
        )
        with pytest.raises(x509.DuplicateExtension) as exc:
            request.extensions

        assert exc.value.oid == x509.OID_BASIC_CONSTRAINTS

    def test_unsupported_critical_extension(self, backend):
        request = _load_cert(
            os.path.join(
                "x509", "requests", "unsupported_extension_critical.pem"
            ),
            x509.load_pem_x509_csr,
            backend
        )
        with pytest.raises(x509.UnsupportedExtension) as exc:
            request.extensions

        assert exc.value.oid == x509.ObjectIdentifier('1.2.3.4')

    def test_unsupported_extension(self, backend):
        request = _load_cert(
            os.path.join(
                "x509", "requests", "unsupported_extension.pem"
            ),
            x509.load_pem_x509_csr,
            backend
        )
        extensions = request.extensions
        assert len(extensions) == 0

    def test_request_basic_constraints(self, backend):
        request = _load_cert(
            os.path.join(
                "x509", "requests", "basic_constraints.pem"
            ),
            x509.load_pem_x509_csr,
            backend
        )
        extensions = request.extensions
        assert isinstance(extensions, x509.Extensions)
        assert list(extensions) == [
            x509.Extension(
                x509.OID_BASIC_CONSTRAINTS,
                True,
                x509.BasicConstraints(ca=True, path_length=1),
            ),
        ]

    def test_public_bytes_pem(self, backend):
        # Load an existing CSR.
        request = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )

        # Encode it to PEM and load it back.
        request = x509.load_pem_x509_csr(request.public_bytes(
            encoding=serialization.Encoding.PEM,
        ), backend)

        # We should recover what we had to start with.
        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
        ]

    def test_public_bytes_der(self, backend):
        # Load an existing CSR.
        request = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )

        # Encode it to DER and load it back.
        request = x509.load_der_x509_csr(request.public_bytes(
            encoding=serialization.Encoding.DER,
        ), backend)

        # We should recover what we had to start with.
        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
        ]

    def test_public_bytes_invalid_encoding(self, backend):
        request = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )

        with pytest.raises(TypeError):
            request.public_bytes('NotAnEncoding')

    @pytest.mark.parametrize(
        ("request_path", "loader_func", "encoding"),
        [
            (
                os.path.join("x509", "requests", "rsa_sha1.pem"),
                x509.load_pem_x509_csr,
                serialization.Encoding.PEM,
            ),
            (
                os.path.join("x509", "requests", "rsa_sha1.der"),
                x509.load_der_x509_csr,
                serialization.Encoding.DER,
            ),
        ]
    )
    def test_public_bytes_match(self, request_path, loader_func, encoding,
                                backend):
        request_bytes = load_vectors_from_file(
            request_path, lambda pemfile: pemfile.read(), mode="rb"
        )
        request = loader_func(request_bytes, backend)
        serialized = request.public_bytes(encoding)
        assert serialized == request_bytes


@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestCertificateSigningRequestBuilder(object):
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_sign_invalid_hash_algorithm(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        builder = x509.CertificateSigningRequestBuilder()
        with pytest.raises(TypeError):
            builder.sign(backend, private_key, 'NotAHash')

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_build_ca_request_with_rsa(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
                x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
                x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
                x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
                x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(
            backend, private_key, hashes.SHA1()
        )

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
        ]
        basic_constraints = request.extensions.get_extension_for_oid(
            x509.OID_BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 2

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_build_nonca_request_with_rsa(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
                x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
                x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
                x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
                x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(
            backend, private_key, hashes.SHA1()
        )

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
        ]
        basic_constraints = request.extensions.get_extension_for_oid(
            x509.OID_BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is False
        assert basic_constraints.value.path_length is None

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    def test_build_ca_request_with_ec(self, backend):
        if backend._lib.OPENSSL_VERSION_NUMBER < 0x10001000:
            pytest.skip("Requires a newer OpenSSL. Must be >= 1.0.1")

        _skip_curve_unsupported(backend, ec.SECT283K1())
        private_key = ec.generate_private_key(ec.SECT283K1(), backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
                x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
                x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
                x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
                x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(
            backend, private_key, hashes.SHA1()
        )

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
        ]
        basic_constraints = request.extensions.get_extension_for_oid(
            x509.OID_BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 2

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    def test_build_ca_request_with_dsa(self, backend):
        if backend._lib.OPENSSL_VERSION_NUMBER < 0x10001000:
            pytest.skip("Requires a newer OpenSSL. Must be >= 1.0.1")

        private_key = DSA_KEY_2048.private_key(backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
                x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
                x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
                x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
                x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(
            backend, private_key, hashes.SHA1()
        )

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, dsa.DSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
        ]
        basic_constraints = request.extensions.get_extension_for_oid(
            x509.OID_BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 2

    def test_add_duplicate_extension(self, backend):
        builder = x509.CertificateSigningRequestBuilder().add_extension(
            x509.BasicConstraints(True, 2), critical=True,
        )
        with pytest.raises(ValueError):
            builder.add_extension(
                x509.BasicConstraints(True, 2), critical=True,
            )

    def test_set_invalid_subject(self, backend):
        builder = x509.CertificateSigningRequestBuilder()
        with pytest.raises(TypeError):
            builder.subject_name('NotAName')

    def test_add_unsupported_extension(self, backend):
        builder = x509.CertificateSigningRequestBuilder()
        with pytest.raises(NotImplementedError):
            builder.add_extension(
                x509.AuthorityKeyIdentifier('keyid', None, None),
                critical=False,
            )


@pytest.mark.requires_backend_interface(interface=DSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestDSACertificate(object):
    def test_load_dsa_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "dsa_selfsigned_ca.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA1)
        public_key = cert.public_key()
        assert isinstance(public_key, dsa.DSAPublicKey)
        if isinstance(public_key, dsa.DSAPublicKeyWithSerialization):
            num = public_key.public_numbers()
            assert num.y == int(
                "4c08bfe5f2d76649c80acf7d431f6ae2124b217abc8c9f6aca776ddfa94"
                "53b6656f13e543684cd5f6431a314377d2abfa068b7080cb8ddc065afc2"
                "dea559f0b584c97a2b235b9b69b46bc6de1aed422a6f341832618bcaae2"
                "198aba388099dafb05ff0b5efecb3b0ae169a62e1c72022af50ae68af3b"
                "033c18e6eec1f7df4692c456ccafb79cc7e08da0a5786e9816ceda651d6"
                "1b4bb7b81c2783da97cea62df67af5e85991fdc13aff10fc60e06586386"
                "b96bb78d65750f542f86951e05a6d81baadbcd35a2e5cad4119923ae6a2"
                "002091a3d17017f93c52970113cdc119970b9074ca506eac91c3dd37632"
                "5df4af6b3911ef267d26623a5a1c5df4a6d13f1c", 16
            )
            assert num.parameter_numbers.g == int(
                "4b7ced71dc353965ecc10d441a9a06fc24943a32d66429dd5ef44d43e67"
                "d789d99770aec32c0415dc92970880872da45fef8dd1e115a3e4801387b"
                "a6d755861f062fd3b6e9ea8e2641152339b828315b1528ee6c7b79458d2"
                "1f3db973f6fc303f9397174c2799dd2351282aa2d8842c357a73495bbaa"
                "c4932786414c55e60d73169f5761036fba29e9eebfb049f8a3b1b7cee6f"
                "3fbfa136205f130bee2cf5b9c38dc1095d4006f2e73335c07352c64130a"
                "1ab2b89f13b48f628d3cc3868beece9bb7beade9f830eacc6fa241425c0"
                "b3fcc0df416a0c89f7bf35668d765ec95cdcfbe9caff49cfc156c668c76"
                "fa6247676a6d3ac945844a083509c6a1b436baca", 16
            )
            assert num.parameter_numbers.p == int(
                "bfade6048e373cd4e48b677e878c8e5b08c02102ae04eb2cb5c46a523a3"
                "af1c73d16b24f34a4964781ae7e50500e21777754a670bd19a7420d6330"
                "84e5556e33ca2c0e7d547ea5f46a07a01bf8669ae3bdec042d9b2ae5e6e"
                "cf49f00ba9dac99ab6eff140d2cedf722ee62c2f9736857971444c25d0a"
                "33d2017dc36d682a1054fe2a9428dda355a851ce6e6d61e03e419fd4ca4"
                "e703313743d86caa885930f62ed5bf342d8165627681e9cc3244ba72aa2"
                "2148400a6bbe80154e855d042c9dc2a3405f1e517be9dea50562f56da93"
                "f6085f844a7e705c1f043e65751c583b80d29103e590ccb26efdaa0893d"
                "833e36468f3907cfca788a3cb790f0341c8a31bf", 16
            )
            assert num.parameter_numbers.q == int(
                "822ff5d234e073b901cf5941f58e1f538e71d40d", 16
            )

    @pytest.mark.parametrize(
        ("path", "loader_func"),
        [
            [
                os.path.join("x509", "requests", "dsa_sha1.pem"),
                x509.load_pem_x509_csr
            ],
            [
                os.path.join("x509", "requests", "dsa_sha1.der"),
                x509.load_der_x509_csr
            ],
        ]
    )
    def test_load_dsa_request(self, path, loader_func, backend):
        request = _load_cert(path, loader_func, backend)
        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, dsa.DSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
        ]


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestECDSACertificate(object):
    def test_load_ecdsa_cert(self, backend):
        _skip_curve_unsupported(backend, ec.SECP384R1())
        cert = _load_cert(
            os.path.join("x509", "ecdsa_root.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        assert isinstance(cert.signature_hash_algorithm, hashes.SHA384)
        public_key = cert.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        if isinstance(public_key, ec.EllipticCurvePublicKeyWithSerialization):
            num = public_key.public_numbers()
            assert num.x == int(
                "dda7d9bb8ab80bfb0b7f21d2f0bebe73f3335d1abc34eadec69bbcd095f"
                "6f0ccd00bba615b51467e9e2d9fee8e630c17", 16
            )
            assert num.y == int(
                "ec0770f5cf842e40839ce83f416d3badd3a4145936789d0343ee10136c7"
                "2deae88a7a16bb543ce67dc23ff031ca3e23e", 16
            )
            assert isinstance(num.curve, ec.SECP384R1)

    def test_load_ecdsa_no_named_curve(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        cert = _load_cert(
            os.path.join("x509", "custom", "ec_no_named_curve.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        with pytest.raises(NotImplementedError):
            cert.public_key()

    @pytest.mark.parametrize(
        ("path", "loader_func"),
        [
            [
                os.path.join("x509", "requests", "ec_sha256.pem"),
                x509.load_pem_x509_csr
            ],
            [
                os.path.join("x509", "requests", "ec_sha256.der"),
                x509.load_der_x509_csr
            ],
        ]
    )
    def test_load_ecdsa_certificate_request(self, path, loader_func, backend):
        _skip_curve_unsupported(backend, ec.SECP384R1())
        request = _load_cert(path, loader_func, backend)
        assert isinstance(request.signature_hash_algorithm, hashes.SHA256)
        public_key = request.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(x509.OID_COUNTRY_NAME, u'US'),
            x509.NameAttribute(x509.OID_STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(x509.OID_LOCALITY_NAME, u'Austin'),
        ]


class TestNameAttribute(object):
    def test_init_bad_oid(self):
        with pytest.raises(TypeError):
            x509.NameAttribute(None, u'value')

    def test_init_bad_value(self):
        with pytest.raises(TypeError):
            x509.NameAttribute(
                x509.ObjectIdentifier('oid'),
                b'bytes'
            )

    def test_eq(self):
        assert x509.NameAttribute(
            x509.ObjectIdentifier('oid'), u'value'
        ) == x509.NameAttribute(
            x509.ObjectIdentifier('oid'), u'value'
        )

    def test_ne(self):
        assert x509.NameAttribute(
            x509.ObjectIdentifier('2.5.4.3'), u'value'
        ) != x509.NameAttribute(
            x509.ObjectIdentifier('2.5.4.5'), u'value'
        )
        assert x509.NameAttribute(
            x509.ObjectIdentifier('oid'), u'value'
        ) != x509.NameAttribute(
            x509.ObjectIdentifier('oid'), u'value2'
        )
        assert x509.NameAttribute(
            x509.ObjectIdentifier('oid'), u'value'
        ) != object()

    def test_repr(self):
        na = x509.NameAttribute(x509.ObjectIdentifier('2.5.4.3'), u'value')
        if six.PY3:
            assert repr(na) == (
                "<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commo"
                "nName)>, value='value')>"
            )
        else:
            assert repr(na) == (
                "<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name=commo"
                "nName)>, value=u'value')>"
            )


class TestObjectIdentifier(object):
    def test_eq(self):
        oid1 = x509.ObjectIdentifier('oid')
        oid2 = x509.ObjectIdentifier('oid')
        assert oid1 == oid2

    def test_ne(self):
        oid1 = x509.ObjectIdentifier('oid')
        assert oid1 != x509.ObjectIdentifier('oid1')
        assert oid1 != object()

    def test_repr(self):
        oid = x509.ObjectIdentifier("2.5.4.3")
        assert repr(oid) == "<ObjectIdentifier(oid=2.5.4.3, name=commonName)>"
        oid = x509.ObjectIdentifier("oid1")
        assert repr(oid) == "<ObjectIdentifier(oid=oid1, name=Unknown OID)>"


class TestName(object):
    def test_eq(self):
        name1 = x509.Name([
            x509.NameAttribute(x509.ObjectIdentifier('oid'), u'value1'),
            x509.NameAttribute(x509.ObjectIdentifier('oid2'), u'value2'),
        ])
        name2 = x509.Name([
            x509.NameAttribute(x509.ObjectIdentifier('oid'), u'value1'),
            x509.NameAttribute(x509.ObjectIdentifier('oid2'), u'value2'),
        ])
        assert name1 == name2

    def test_ne(self):
        name1 = x509.Name([
            x509.NameAttribute(x509.ObjectIdentifier('oid'), u'value1'),
            x509.NameAttribute(x509.ObjectIdentifier('oid2'), u'value2'),
        ])
        name2 = x509.Name([
            x509.NameAttribute(x509.ObjectIdentifier('oid2'), u'value2'),
            x509.NameAttribute(x509.ObjectIdentifier('oid'), u'value1'),
        ])
        assert name1 != name2
        assert name1 != object()

    def test_repr(self):
        name = x509.Name([
            x509.NameAttribute(x509.OID_COMMON_NAME, u'cryptography.io'),
            x509.NameAttribute(x509.OID_ORGANIZATION_NAME, u'PyCA'),
        ])

        if six.PY3:
            assert repr(name) == (
                "<Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name"
                "=commonName)>, value='cryptography.io')>, <NameAttribute(oid="
                "<ObjectIdentifier(oid=2.5.4.10, name=organizationName)>, valu"
                "e='PyCA')>])>"
            )
        else:
            assert repr(name) == (
                "<Name([<NameAttribute(oid=<ObjectIdentifier(oid=2.5.4.3, name"
                "=commonName)>, value=u'cryptography.io')>, <NameAttribute(oid"
                "=<ObjectIdentifier(oid=2.5.4.10, name=organizationName)>, val"
                "ue=u'PyCA')>])>"
            )
