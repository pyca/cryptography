# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import datetime
import os

import pytest

from cryptography import x509
from cryptography.exceptions import InvalidX509Version
from cryptography.hazmat.backends.interfaces import (
    DSABackend, EllipticCurveBackend, RSABackend, X509Backend
)
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives.asymmetric import ec

from .hazmat.primitives.test_ec import _skip_curve_unsupported
from .utils import load_vectors_from_file


def _load_der_cert(name, backend):
    cert = load_vectors_from_file(
        os.path.join(
            "x509", "PKITS_data", "certs", name),
        lambda derfile: x509.load_der_x509_certificate(
            derfile.read(), backend
        )
    )
    return cert


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestRSAX509Certificate(object):
    def test_load_pem_cert(self, backend):
        cert = load_vectors_from_file(
            os.path.join(
                "x509", "custom", "post2000utctime.pem"),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            )
        )
        assert cert

    def test_load_der_cert(self, backend):
        cert = load_vectors_from_file(
            os.path.join(
                "x509", "PKITS_data", "certs", "GoodCACert.crt"),
            lambda derfile: x509.load_der_x509_certificate(
                derfile.read(), backend
            )
        )
        assert cert

    def test_load_good_ca_cert(self, backend):
        cert = _load_der_cert("GoodCACert.crt", backend)

        assert cert.not_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.serial == 2
        public_key = cert.public_key()
        assert isinstance(public_key, interfaces.RSAPublicKey)
        assert cert.version == x509.X509Version.v3

    def test_utc_pre_2000_not_before_cert(self, backend):
        cert = _load_der_cert(
            "Validpre2000UTCnotBeforeDateTest3EE.crt",
            backend
        )

        assert cert.not_before == datetime.datetime(1950, 1, 1, 12, 1)

    def test_pre_2000_utc_not_after_cert(self, backend):
        cert = _load_der_cert(
            "Invalidpre2000UTCEEnotAfterDateTest7EE.crt",
            backend
        )

        assert cert.not_after == datetime.datetime(1999, 1, 1, 12, 1)

    def test_post_2000_utc_cert(self, backend):
        cert = load_vectors_from_file(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            )
        )
        assert cert.not_before == datetime.datetime(2014, 11, 26, 21, 41, 20)
        assert cert.not_after == datetime.datetime(2014, 12, 26, 21, 41, 20)

    def test_generalized_time_not_before_cert(self, backend):
        cert = _load_der_cert(
            "ValidGeneralizedTimenotBeforeDateTest4EE.crt",
            backend
        )

        assert cert.not_before == datetime.datetime(2002, 1, 1, 12, 1)
        assert cert.not_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.version == x509.X509Version.v3

    def test_generalized_time_not_after_cert(self, backend):
        cert = _load_der_cert(
            "ValidGeneralizedTimenotAfterDateTest8EE.crt",
            backend
        )
        assert cert.not_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_after == datetime.datetime(2050, 1, 1, 12, 1)
        assert cert.version == x509.X509Version.v3

    def test_invalid_version_cert(self, backend):
        cert = load_vectors_from_file(
            os.path.join("x509", "custom", "invalid_version.pem"),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            )
        )
        with pytest.raises(InvalidX509Version):
            cert.version

    def test_version_1_cert(self, backend):
        cert = load_vectors_from_file(
            os.path.join("x509", "v1_cert.pem"),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            )
        )
        assert cert.version == x509.X509Version.v1

    def test_invalid_pem(self, backend):
        with pytest.raises(ValueError):
            x509.load_pem_x509_certificate(b"notacert", backend)

    def test_invalid_der(self, backend):
        with pytest.raises(ValueError):
            x509.load_der_x509_certificate(b"notacert", backend)


@pytest.mark.requires_backend_interface(interface=DSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestDSAX509Certificate(object):
    def test_load_dsa_cert(self, backend):
        cert = load_vectors_from_file(
            os.path.join("x509", "custom", "dsa_root.pem"),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            )
        )
        public_key = cert.public_key()
        assert isinstance(public_key, interfaces.DSAPublicKey)


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestECDSAX509Certificate(object):
    def test_load_ecdsa_cert(self, backend):
        _skip_curve_unsupported(backend, ec.SECP384R1())
        cert = load_vectors_from_file(
            os.path.join("x509", "ecdsa_root.pem"),
            lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read(), backend
            )
        )
        public_key = cert.public_key()
        assert isinstance(public_key, interfaces.EllipticCurvePublicKey)
