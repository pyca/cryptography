# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import datetime
import ipaddress
import os

import pytest

import six

from cryptography import utils, x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.interfaces import (
    DSABackend, EllipticCurveBackend, RSABackend, X509Backend
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.x509.oid import (
    AuthorityInformationAccessOID, ExtendedKeyUsageOID, ExtensionOID, NameOID
)

from .hazmat.primitives.fixtures_dsa import DSA_KEY_2048
from .hazmat.primitives.fixtures_rsa import RSA_KEY_2048, RSA_KEY_512
from .hazmat.primitives.test_ec import _skip_curve_unsupported
from .utils import load_vectors_from_file


@utils.register_interface(x509.ExtensionType)
class DummyExtension(object):
    oid = x509.ObjectIdentifier("1.2.3.4")


@utils.register_interface(x509.GeneralName)
class FakeGeneralName(object):
    def __init__(self, value):
        self._value = value

    value = utils.read_only_property("_value")


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
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, u'Test Certificates 2011'
            ),
            x509.NameAttribute(NameOID.COMMON_NAME, u'Good CA')
        ]
        assert issuer.get_attributes_for_oid(NameOID.COMMON_NAME) == [
            x509.NameAttribute(NameOID.COMMON_NAME, u'Good CA')
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
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'CA'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Illinois'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Chicago'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Zero, LLC'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'One, LLC'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'common name 0'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'common name 1'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'OU 0'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, u'OU 1'),
            x509.NameAttribute(NameOID.DN_QUALIFIER, u'dnQualifier0'),
            x509.NameAttribute(NameOID.DN_QUALIFIER, u'dnQualifier1'),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, u'123'),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, u'456'),
            x509.NameAttribute(NameOID.TITLE, u'Title 0'),
            x509.NameAttribute(NameOID.TITLE, u'Title 1'),
            x509.NameAttribute(NameOID.SURNAME, u'Surname 0'),
            x509.NameAttribute(NameOID.SURNAME, u'Surname 1'),
            x509.NameAttribute(NameOID.GIVEN_NAME, u'Given Name 0'),
            x509.NameAttribute(NameOID.GIVEN_NAME, u'Given Name 1'),
            x509.NameAttribute(NameOID.PSEUDONYM, u'Incognito 0'),
            x509.NameAttribute(NameOID.PSEUDONYM, u'Incognito 1'),
            x509.NameAttribute(NameOID.GENERATION_QUALIFIER, u'Last Gen'),
            x509.NameAttribute(NameOID.GENERATION_QUALIFIER, u'Next Gen'),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'dc0'),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'dc1'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'test0@test.local'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'test1@test.local'),
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
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME, u'Test Certificates 2011'
            ),
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                u'Valid pre2000 UTC notBefore Date EE Certificate Test3'
            )
        ]
        assert subject.get_attributes_for_oid(NameOID.COMMON_NAME) == [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
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
        assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME) == [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
                u'We heart UTF8!\u2122'
            )
        ]
        assert cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME) == [
            x509.NameAttribute(
                NameOID.COMMON_NAME,
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
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'AU'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'DE'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'New York'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'San Francisco'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Ithaca'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Org Zero, LLC'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'Org One, LLC'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'CN 0'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'CN 1'),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, u'Engineering 0'
            ),
            x509.NameAttribute(
                NameOID.ORGANIZATIONAL_UNIT_NAME, u'Engineering 1'
            ),
            x509.NameAttribute(NameOID.DN_QUALIFIER, u'qualified0'),
            x509.NameAttribute(NameOID.DN_QUALIFIER, u'qualified1'),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, u'789'),
            x509.NameAttribute(NameOID.SERIAL_NUMBER, u'012'),
            x509.NameAttribute(NameOID.TITLE, u'Title IX'),
            x509.NameAttribute(NameOID.TITLE, u'Title X'),
            x509.NameAttribute(NameOID.SURNAME, u'Last 0'),
            x509.NameAttribute(NameOID.SURNAME, u'Last 1'),
            x509.NameAttribute(NameOID.GIVEN_NAME, u'First 0'),
            x509.NameAttribute(NameOID.GIVEN_NAME, u'First 1'),
            x509.NameAttribute(NameOID.PSEUDONYM, u'Guy Incognito 0'),
            x509.NameAttribute(NameOID.PSEUDONYM, u'Guy Incognito 1'),
            x509.NameAttribute(NameOID.GENERATION_QUALIFIER, u'32X'),
            x509.NameAttribute(NameOID.GENERATION_QUALIFIER, u'Dreamcast'),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'dc2'),
            x509.NameAttribute(NameOID.DOMAIN_COMPONENT, u'dc3'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'test2@test.local'),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, u'test3@test.local'),
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

    def test_hash(self, backend):
        cert1 = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        cert2 = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            x509.load_pem_x509_certificate,
            backend
        )
        cert3 = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "ValidGeneralizedTimenotAfterDateTest8EE.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )

        assert hash(cert1) == hash(cert2)
        assert hash(cert1) != hash(cert3)

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
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
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

        assert exc.value.oid == ExtensionOID.BASIC_CONSTRAINTS

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
                ExtensionOID.BASIC_CONSTRAINTS,
                True,
                x509.BasicConstraints(ca=True, path_length=1),
            ),
        ]

    def test_subject_alt_name(self, backend):
        request = _load_cert(
            os.path.join("x509", "requests", "san_rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend,
        )
        ext = request.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert list(ext.value) == [
            x509.DNSName(u"cryptography.io"),
            x509.DNSName(u"sub.cryptography.io"),
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
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
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
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
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

    def test_eq(self, backend):
        request1 = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        request2 = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )

        assert request1 == request2

    def test_ne(self, backend):
        request1 = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        request2 = _load_cert(
            os.path.join("x509", "requests", "san_rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )

        assert request1 != request2
        assert request1 != object()

    def test_hash(self, backend):
        request1 = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        request2 = _load_cert(
            os.path.join("x509", "requests", "rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )
        request3 = _load_cert(
            os.path.join("x509", "requests", "san_rsa_sha1.pem"),
            x509.load_pem_x509_csr,
            backend
        )

        assert hash(request1) == hash(request2)
        assert hash(request1) != hash(request3)

    def test_build_cert(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), True,
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"cryptography.io")]),
            critical=False,
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA1(), backend)

        assert cert.version is x509.Version.v3
        assert cert.not_valid_before == not_valid_before
        assert cert.not_valid_after == not_valid_after
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is False
        assert basic_constraints.value.path_length is None
        subject_alternative_name = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert list(subject_alternative_name.value) == [
            x509.DNSName(u"cryptography.io"),
        ]


class TestCertificateBuilder(object):
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_checks_for_unsupported_extensions(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            private_key.public_key()
        ).serial_number(
            777
        ).not_valid_before(
            datetime.datetime(1999, 1, 1)
        ).not_valid_after(
            datetime.datetime(2020, 1, 1)
        ).add_extension(
            DummyExtension(), False
        )

        with pytest.raises(NotImplementedError):
            builder.sign(private_key, hashes.SHA1(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_subject_name(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )
        with pytest.raises(ValueError):
            builder.sign(subject_private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_issuer_name(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().serial_number(
            777
        ).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )
        with pytest.raises(ValueError):
            builder.sign(subject_private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_public_key(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )
        with pytest.raises(ValueError):
            builder.sign(subject_private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_not_valid_before(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )
        with pytest.raises(ValueError):
            builder.sign(subject_private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_not_valid_after(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.sign(subject_private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_serial_number(self, backend):
        subject_private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder().issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )
        with pytest.raises(ValueError):
            builder.sign(subject_private_key, hashes.SHA256(), backend)

    def test_issuer_name_must_be_a_name_type(self):
        builder = x509.CertificateBuilder()

        with pytest.raises(TypeError):
            builder.issuer_name("subject")

        with pytest.raises(TypeError):
            builder.issuer_name(object)

    def test_issuer_name_may_only_be_set_once(self):
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])
        builder = x509.CertificateBuilder().issuer_name(name)

        with pytest.raises(ValueError):
            builder.issuer_name(name)

    def test_subject_name_must_be_a_name_type(self):
        builder = x509.CertificateBuilder()

        with pytest.raises(TypeError):
            builder.subject_name("subject")

        with pytest.raises(TypeError):
            builder.subject_name(object)

    def test_subject_name_may_only_be_set_once(self):
        name = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])
        builder = x509.CertificateBuilder().subject_name(name)

        with pytest.raises(ValueError):
            builder.subject_name(name)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_public_key_must_be_public_key(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder()

        with pytest.raises(TypeError):
            builder.public_key(private_key)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_public_key_may_only_be_set_once(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        public_key = private_key.public_key()
        builder = x509.CertificateBuilder().public_key(public_key)

        with pytest.raises(ValueError):
            builder.public_key(public_key)

    def test_serial_number_must_be_an_integer_type(self):
        with pytest.raises(TypeError):
            x509.CertificateBuilder().serial_number(10.0)

    def test_serial_number_must_be_non_negative(self):
        with pytest.raises(ValueError):
            x509.CertificateBuilder().serial_number(-10)

    def test_serial_number_must_be_less_than_160_bits_long(self):
        with pytest.raises(ValueError):
            # 2 raised to the 160th power is actually 161 bits
            x509.CertificateBuilder().serial_number(2 ** 160)

    def test_serial_number_may_only_be_set_once(self):
        builder = x509.CertificateBuilder().serial_number(10)

        with pytest.raises(ValueError):
            builder.serial_number(20)

    def test_invalid_not_valid_after(self):
        with pytest.raises(TypeError):
            x509.CertificateBuilder().not_valid_after(104204304504)

        with pytest.raises(TypeError):
            x509.CertificateBuilder().not_valid_after(datetime.time())

        with pytest.raises(ValueError):
            x509.CertificateBuilder().not_valid_after(
                datetime.datetime(1960, 8, 10)
            )

    def test_not_valid_after_may_only_be_set_once(self):
        builder = x509.CertificateBuilder().not_valid_after(
            datetime.datetime.now()
        )

        with pytest.raises(ValueError):
            builder.not_valid_after(
                datetime.datetime.now()
            )

    def test_invalid_not_valid_before(self):
        with pytest.raises(TypeError):
            x509.CertificateBuilder().not_valid_before(104204304504)

        with pytest.raises(TypeError):
            x509.CertificateBuilder().not_valid_before(datetime.time())

        with pytest.raises(ValueError):
            x509.CertificateBuilder().not_valid_before(
                datetime.datetime(1960, 8, 10)
            )

    def test_not_valid_before_may_only_be_set_once(self):
        builder = x509.CertificateBuilder().not_valid_before(
            datetime.datetime.now()
        )

        with pytest.raises(ValueError):
            builder.not_valid_before(
                datetime.datetime.now()
            )

    def test_add_extension_checks_for_duplicates(self):
        builder = x509.CertificateBuilder().add_extension(
            x509.BasicConstraints(ca=False, path_length=None), True,
        )

        with pytest.raises(ValueError):
            builder.add_extension(
                x509.BasicConstraints(ca=False, path_length=None), True,
            )

    def test_add_invalid_extension_type(self):
        builder = x509.CertificateBuilder()

        with pytest.raises(TypeError):
            builder.add_extension(object(), False)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_with_unsupported_hash(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).serial_number(
            1
        ).public_key(
            private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2032, 1, 1, 12, 1)
        )

        with pytest.raises(TypeError):
            builder.sign(private_key, object(), backend)

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_with_dsa_private_key_is_unsupported(self, backend):
        if backend._lib.OPENSSL_VERSION_NUMBER >= 0x10001000:
            pytest.skip("Requires an older OpenSSL. Must be < 1.0.1")

        private_key = DSA_KEY_2048.private_key(backend)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).serial_number(
            1
        ).public_key(
            private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2032, 1, 1, 12, 1)
        )

        with pytest.raises(NotImplementedError):
            builder.sign(private_key, hashes.SHA512(), backend)

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_with_ec_private_key_is_unsupported(self, backend):
        if backend._lib.OPENSSL_VERSION_NUMBER >= 0x10001000:
            pytest.skip("Requires an older OpenSSL. Must be < 1.0.1")

        _skip_curve_unsupported(backend, ec.SECP256R1())
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).serial_number(
            1
        ).public_key(
            private_key.public_key()
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2032, 1, 1, 12, 1)
        )

        with pytest.raises(NotImplementedError):
            builder.sign(private_key, hashes.SHA512(), backend)

    @pytest.mark.parametrize(
        "cdp",
        [
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=None,
                    relative_name=x509.Name([
                        x509.NameAttribute(
                            NameOID.COMMON_NAME,
                            u"indirect CRL for indirectCRL CA3"
                        ),
                    ]),
                    reasons=None,
                    crl_issuer=[x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                            x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME,
                                u"Test Certificates 2011"
                            ),
                            x509.NameAttribute(
                                NameOID.ORGANIZATIONAL_UNIT_NAME,
                                u"indirectCRL CA3 cRLIssuer"
                            ),
                        ])
                    )],
                )
            ]),
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                        ])
                    )],
                    relative_name=None,
                    reasons=None,
                    crl_issuer=[x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME,
                                u"cryptography Testing"
                            ),
                        ])
                    )],
                )
            ]),
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[
                        x509.UniformResourceIdentifier(
                            u"http://myhost.com/myca.crl"
                        ),
                        x509.UniformResourceIdentifier(
                            u"http://backup.myhost.com/myca.crl"
                        )
                    ],
                    relative_name=None,
                    reasons=frozenset([
                        x509.ReasonFlags.key_compromise,
                        x509.ReasonFlags.ca_compromise
                    ]),
                    crl_issuer=[x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, u"cryptography CA"
                            ),
                        ])
                    )],
                )
            ]),
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        u"http://domain.com/some.crl"
                    )],
                    relative_name=None,
                    reasons=frozenset([
                        x509.ReasonFlags.key_compromise,
                        x509.ReasonFlags.ca_compromise,
                        x509.ReasonFlags.affiliation_changed,
                        x509.ReasonFlags.superseded,
                        x509.ReasonFlags.privilege_withdrawn,
                        x509.ReasonFlags.cessation_of_operation,
                        x509.ReasonFlags.aa_compromise,
                        x509.ReasonFlags.certificate_hold,
                    ]),
                    crl_issuer=None
                )
            ]),
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=None,
                    relative_name=None,
                    reasons=None,
                    crl_issuer=[x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, u"cryptography CA"
                            ),
                        ])
                    )],
                )
            ]),
            x509.CRLDistributionPoints([
                x509.DistributionPoint(
                    full_name=[x509.UniformResourceIdentifier(
                        u"http://domain.com/some.crl"
                    )],
                    relative_name=None,
                    reasons=frozenset([x509.ReasonFlags.aa_compromise]),
                    crl_issuer=None
                )
            ])
        ]
    )
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_crl_distribution_points(self, backend, cdp):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        builder = x509.CertificateBuilder().serial_number(
            4444444
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            cdp,
            critical=False,
        ).not_valid_before(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).not_valid_after(
            datetime.datetime(2030, 12, 31, 8, 30)
        )

        cert = builder.sign(issuer_private_key, hashes.SHA1(), backend)

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        assert ext.critical is False
        assert ext.value == cdp

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_cert_with_dsa_private_key(self, backend):
        if backend._lib.OPENSSL_VERSION_NUMBER < 0x10001000:
            pytest.skip("Requires a newer OpenSSL. Must be >= 1.0.1")

        issuer_private_key = DSA_KEY_2048.private_key(backend)
        subject_private_key = DSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), True,
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"cryptography.io")]),
            critical=False,
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA1(), backend)

        assert cert.version is x509.Version.v3
        assert cert.not_valid_before == not_valid_before
        assert cert.not_valid_after == not_valid_after
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is False
        assert basic_constraints.value.path_length is None
        subject_alternative_name = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert list(subject_alternative_name.value) == [
            x509.DNSName(u"cryptography.io"),
        ]

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_cert_with_ec_private_key(self, backend):
        if backend._lib.OPENSSL_VERSION_NUMBER < 0x10001000:
            pytest.skip("Requires a newer OpenSSL. Must be >= 1.0.1")

        _skip_curve_unsupported(backend, ec.SECP256R1())
        issuer_private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        subject_private_key = ec.generate_private_key(ec.SECP256R1(), backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), True,
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"cryptography.io")]),
            critical=False,
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA1(), backend)

        assert cert.version is x509.Version.v3
        assert cert.not_valid_before == not_valid_before
        assert cert.not_valid_after == not_valid_after
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is False
        assert basic_constraints.value.path_length is None
        subject_alternative_name = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert list(subject_alternative_name.value) == [
            x509.DNSName(u"cryptography.io"),
        ]

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_cert_with_rsa_key_too_small(self, backend):
        issuer_private_key = RSA_KEY_512.private_key(backend)
        subject_private_key = RSA_KEY_512.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        with pytest.raises(ValueError):
            builder.sign(issuer_private_key, hashes.SHA512(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_issuer_alt_name(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).public_key(
            subject_private_key.public_key()
        ).serial_number(
            123
        ).add_extension(
            x509.IssuerAlternativeName([
                x509.DNSName(u"myissuer"),
                x509.RFC822Name(u"email@domain.com"),
            ]), critical=False
        ).sign(issuer_private_key, hashes.SHA256(), backend)

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.ISSUER_ALTERNATIVE_NAME
        )
        assert ext.critical is False
        assert ext.value == x509.IssuerAlternativeName([
            x509.DNSName(u"myissuer"),
            x509.RFC822Name(u"email@domain.com"),
        ])

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_extended_key_usage(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).public_key(
            subject_private_key.public_key()
        ).serial_number(
            123
        ).add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CODE_SIGNING,
            ]), critical=False
        ).sign(issuer_private_key, hashes.SHA256(), backend)

        eku = cert.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )
        assert eku.critical is False
        assert eku.value == x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CODE_SIGNING,
        ])

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_inhibit_any_policy(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).public_key(
            subject_private_key.public_key()
        ).serial_number(
            123
        ).add_extension(
            x509.InhibitAnyPolicy(3), critical=False
        ).sign(issuer_private_key, hashes.SHA256(), backend)

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.INHIBIT_ANY_POLICY
        )
        assert ext.value == x509.InhibitAnyPolicy(3)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_key_usage(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        cert = x509.CertificateBuilder().subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        ).public_key(
            subject_private_key.public_key()
        ).serial_number(
            123
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=False
        ).sign(issuer_private_key, hashes.SHA256(), backend)

        ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        assert ext.critical is False
        assert ext.value == x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )


@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestCertificateSigningRequestBuilder(object):
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_sign_invalid_hash_algorithm(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([])
        )
        with pytest.raises(TypeError):
            builder.sign(private_key, 'NotAHash', backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_no_subject_name(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        builder = x509.CertificateSigningRequestBuilder()
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_build_ca_request_with_rsa(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(private_key, hashes.SHA1(), backend)

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
        ]
        basic_constraints = request.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 2

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_build_ca_request_with_unicode(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME,
                                   u'PyCA\U0001f37a'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(private_key, hashes.SHA1(), backend)

        loaded_request = x509.load_pem_x509_csr(
            request.public_bytes(encoding=serialization.Encoding.PEM), backend
        )
        subject = loaded_request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA\U0001f37a'),
        ]

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_build_nonca_request_with_rsa(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(private_key, hashes.SHA1(), backend)

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ]
        basic_constraints = request.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is False
        assert basic_constraints.value.path_length is None

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    def test_build_ca_request_with_ec(self, backend):
        if backend._lib.OPENSSL_VERSION_NUMBER < 0x10001000:
            pytest.skip("Requires a newer OpenSSL. Must be >= 1.0.1")

        _skip_curve_unsupported(backend, ec.SECP256R1())
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)

        request = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(private_key, hashes.SHA1(), backend)

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, ec.EllipticCurvePublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
        ]
        basic_constraints = request.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
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
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(private_key, hashes.SHA1(), backend)

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, dsa.DSAPublicKey)
        subject = request.subject
        assert isinstance(subject, x509.Name)
        assert list(subject) == [
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ]
        basic_constraints = request.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 2

    def test_add_duplicate_extension(self):
        builder = x509.CertificateSigningRequestBuilder().add_extension(
            x509.BasicConstraints(True, 2), critical=True,
        )
        with pytest.raises(ValueError):
            builder.add_extension(
                x509.BasicConstraints(True, 2), critical=True,
            )

    def test_set_invalid_subject(self):
        builder = x509.CertificateSigningRequestBuilder()
        with pytest.raises(TypeError):
            builder.subject_name('NotAName')

    def test_add_invalid_extension_type(self):
        builder = x509.CertificateSigningRequestBuilder()

        with pytest.raises(TypeError):
            builder.add_extension(object(), False)

    def test_add_unsupported_extension(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"cryptography.io")]),
            critical=False,
        ).add_extension(
            DummyExtension(), False
        )
        with pytest.raises(NotImplementedError):
            builder.sign(private_key, hashes.SHA256(), backend)

    def test_key_usage(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateSigningRequestBuilder()
        request = builder.subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=True,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=False
        ).sign(private_key, hashes.SHA256(), backend)
        assert len(request.extensions) == 1
        ext = request.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        assert ext.critical is False
        assert ext.value == x509.KeyUsage(
            digital_signature=True,
            content_commitment=True,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False
        )

    def test_key_usage_key_agreement_bit(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateSigningRequestBuilder()
        request = builder.subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=True,
                crl_sign=False,
                encipher_only=False,
                decipher_only=True
            ),
            critical=False
        ).sign(private_key, hashes.SHA256(), backend)
        assert len(request.extensions) == 1
        ext = request.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        assert ext.critical is False
        assert ext.value == x509.KeyUsage(
            digital_signature=False,
            content_commitment=False,
            key_encipherment=False,
            data_encipherment=False,
            key_agreement=True,
            key_cert_sign=True,
            crl_sign=False,
            encipher_only=False,
            decipher_only=True
        )

    def test_add_two_extensions(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateSigningRequestBuilder()
        request = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"cryptography.io")]),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=2), critical=True
        ).sign(private_key, hashes.SHA1(), backend)

        assert isinstance(request.signature_hash_algorithm, hashes.SHA1)
        public_key = request.public_key()
        assert isinstance(public_key, rsa.RSAPublicKey)
        basic_constraints = request.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        )
        assert basic_constraints.value.ca is True
        assert basic_constraints.value.path_length == 2
        ext = request.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert list(ext.value) == [x509.DNSName(u"cryptography.io")]

    def test_set_subject_twice(self):
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            ])
        )
        with pytest.raises(ValueError):
            builder.subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
                ])
            )

    def test_subject_alt_names(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        csr = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"SAN"),
            ])
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"example.com"),
                x509.DNSName(u"*.example.com"),
                x509.RegisteredID(x509.ObjectIdentifier("1.2.3.4.5.6.7")),
                x509.DirectoryName(x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, u'PyCA'),
                    x509.NameAttribute(
                        NameOID.ORGANIZATION_NAME, u'We heart UTF8!\u2122'
                    )
                ])),
                x509.IPAddress(ipaddress.ip_address(u"127.0.0.1")),
                x509.IPAddress(ipaddress.ip_address(u"ff::")),
                x509.OtherName(
                    type_id=x509.ObjectIdentifier("1.2.3.3.3.3"),
                    value=b"0\x03\x02\x01\x05"
                ),
                x509.RFC822Name(u"test@example.com"),
                x509.RFC822Name(u"email"),
                x509.RFC822Name(u"email@em\xe5\xefl.com"),
                x509.UniformResourceIdentifier(
                    u"https://\u043f\u044b\u043a\u0430.cryptography"
                ),
                x509.UniformResourceIdentifier(
                    u"gopher://cryptography:70/some/path"
                ),
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256(), backend)

        assert len(csr.extensions) == 1
        ext = csr.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        assert not ext.critical
        assert ext.oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        assert list(ext.value) == [
            x509.DNSName(u"example.com"),
            x509.DNSName(u"*.example.com"),
            x509.RegisteredID(x509.ObjectIdentifier("1.2.3.4.5.6.7")),
            x509.DirectoryName(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u'PyCA'),
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME, u'We heart UTF8!\u2122'
                ),
            ])),
            x509.IPAddress(ipaddress.ip_address(u"127.0.0.1")),
            x509.IPAddress(ipaddress.ip_address(u"ff::")),
            x509.OtherName(
                type_id=x509.ObjectIdentifier("1.2.3.3.3.3"),
                value=b"0\x03\x02\x01\x05"
            ),
            x509.RFC822Name(u"test@example.com"),
            x509.RFC822Name(u"email"),
            x509.RFC822Name(u"email@em\xe5\xefl.com"),
            x509.UniformResourceIdentifier(
                u"https://\u043f\u044b\u043a\u0430.cryptography"
            ),
            x509.UniformResourceIdentifier(
                u"gopher://cryptography:70/some/path"
            ),
        ]

    def test_invalid_asn1_othername(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"SAN"),
            ])
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.OtherName(
                    type_id=x509.ObjectIdentifier("1.2.3.3.3.3"),
                    value=b"\x01\x02\x01\x05"
                ),
            ]),
            critical=False,
        )
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    def test_subject_alt_name_unsupported_general_name(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)

        builder = x509.CertificateSigningRequestBuilder().subject_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"SAN"),
            ])
        ).add_extension(
            x509.SubjectAlternativeName([FakeGeneralName("")]),
            critical=False,
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    def test_extended_key_usage(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateSigningRequestBuilder()
        request = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).add_extension(
            x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH,
                ExtendedKeyUsageOID.SERVER_AUTH,
                ExtendedKeyUsageOID.CODE_SIGNING,
            ]), critical=False
        ).sign(private_key, hashes.SHA256(), backend)

        eku = request.extensions.get_extension_for_oid(
            ExtensionOID.EXTENDED_KEY_USAGE
        )
        assert eku.critical is False
        assert eku.value == x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.CLIENT_AUTH,
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CODE_SIGNING,
        ])

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    def test_rsa_key_too_small(self, backend):
        private_key = rsa.generate_private_key(65537, 512, backend)
        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        )

        with pytest.raises(ValueError) as exc:
            builder.sign(private_key, hashes.SHA512(), backend)

        assert str(exc.value) == "Digest too big for RSA key"

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_cert_with_aia(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        aia = x509.AuthorityInformationAccess([
            x509.AccessDescription(
                AuthorityInformationAccessOID.OCSP,
                x509.UniformResourceIdentifier(u"http://ocsp.domain.com")
            ),
            x509.AccessDescription(
                AuthorityInformationAccessOID.CA_ISSUERS,
                x509.UniformResourceIdentifier(u"http://domain.com/ca.crt")
            )
        ])

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            aia, critical=False
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA1(), backend)

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_INFORMATION_ACCESS
        )
        assert ext.value == aia

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_cert_with_ski(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        ski = x509.SubjectKeyIdentifier.from_public_key(
            subject_private_key.public_key()
        )

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            ski, critical=False
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA1(), backend)

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_KEY_IDENTIFIER
        )
        assert ext.value == ski

    @pytest.mark.parametrize(
        "aki",
        [
            x509.AuthorityKeyIdentifier(
                b"\xc3\x9c\xf3\xfc\xd3F\x084\xbb\xceF\x7f\xa0|[\xf3\xe2\x08"
                b"\xcbY",
                None,
                None
            ),
            x509.AuthorityKeyIdentifier(
                b"\xc3\x9c\xf3\xfc\xd3F\x084\xbb\xceF\x7f\xa0|[\xf3\xe2\x08"
                b"\xcbY",
                [
                    x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME, u"PyCA"
                            ),
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, u"cryptography CA"
                            )
                        ])
                    )
                ],
                333
            ),
            x509.AuthorityKeyIdentifier(
                None,
                [
                    x509.DirectoryName(
                        x509.Name([
                            x509.NameAttribute(
                                NameOID.ORGANIZATION_NAME, u"PyCA"
                            ),
                            x509.NameAttribute(
                                NameOID.COMMON_NAME, u"cryptography CA"
                            )
                        ])
                    )
                ],
                333
            ),
        ]
    )
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_build_cert_with_aki(self, aki, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            aki, critical=False
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA256(), backend)

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.AUTHORITY_KEY_IDENTIFIER
        )
        assert ext.value == aki

    def test_ocsp_nocheck(self, backend):
        issuer_private_key = RSA_KEY_2048.private_key(backend)
        subject_private_key = RSA_KEY_2048.private_key(backend)

        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)

        builder = x509.CertificateBuilder().serial_number(
            777
        ).issuer_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        ])).public_key(
            subject_private_key.public_key()
        ).add_extension(
            x509.OCSPNoCheck(), critical=False
        ).not_valid_before(
            not_valid_before
        ).not_valid_after(
            not_valid_after
        )

        cert = builder.sign(issuer_private_key, hashes.SHA256(), backend)

        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.OCSP_NO_CHECK
        )
        assert isinstance(ext.value, x509.OCSPNoCheck)


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
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
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
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
            x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'Texas'),
            x509.NameAttribute(NameOID.LOCALITY_NAME, u'Austin'),
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
            x509.NameAttribute(NameOID.COMMON_NAME, u'cryptography.io'),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u'PyCA'),
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
