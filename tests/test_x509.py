# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import datetime
import os

import pytest

from cryptography import x509
from cryptography.hazmat.backends.interfaces import (
    DSABackend, EllipticCurveBackend, RSABackend, X509Backend
)
from cryptography.hazmat.primitives import hashes, interfaces
from cryptography.hazmat.primitives.asymmetric import ec

from .hazmat.primitives.test_ec import _skip_curve_unsupported
from .utils import load_vectors_from_file


def _load_cert(filename, fmt, backend):
    if fmt == "pem":
        loader = x509.load_pem_x509_certificate
    else:
        loader = x509.load_der_x509_certificate

    cert = load_vectors_from_file(
        filename=filename,
        loader=lambda pemfile: loader(pemfile.read(), backend),
        mode="rb"
    )
    return cert


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestRSAX509Certificate(object):
    def test_load_pem_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            "pem",
            backend
        )
        assert isinstance(cert, interfaces.X509Certificate)

    def test_load_der_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            "der",
            backend
        )
        assert isinstance(cert, interfaces.X509Certificate)

    def test_load_good_ca_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "PKITS_data", "certs", "GoodCACert.crt"),
            "der",
            backend
        )

        assert cert.not_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.serial == 2
        public_key = cert.public_key()
        assert isinstance(public_key, interfaces.RSAPublicKey)
        assert cert.version == x509.X509Version.v3
        fingerprint = binascii.hexlify(cert.fingerprint(hashes.SHA1()))
        assert fingerprint == b"6f49779533d565e8b7c1062503eab41492c38e4d"

    def test_utc_pre_2000_not_before_cert(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "Validpre2000UTCnotBeforeDateTest3EE.crt"
            ),
            "der",
            backend
        )

        assert cert.not_before == datetime.datetime(1950, 1, 1, 12, 1)

    def test_pre_2000_utc_not_after_cert(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "Invalidpre2000UTCEEnotAfterDateTest7EE.crt"
            ),
            "der",
            backend
        )

        assert cert.not_after == datetime.datetime(1999, 1, 1, 12, 1)

    def test_post_2000_utc_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "post2000utctime.pem"),
            "pem",
            backend
        )
        assert cert.not_before == datetime.datetime(2014, 11, 26, 21, 41, 20)
        assert cert.not_after == datetime.datetime(2014, 12, 26, 21, 41, 20)

    def test_generalized_time_not_before_cert(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "ValidGeneralizedTimenotBeforeDateTest4EE.crt"
            ),
            "der",
            backend
        )
        assert cert.not_before == datetime.datetime(2002, 1, 1, 12, 1)
        assert cert.not_after == datetime.datetime(2030, 12, 31, 8, 30)
        assert cert.version == x509.X509Version.v3

    def test_generalized_time_not_after_cert(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "ValidGeneralizedTimenotAfterDateTest8EE.crt"
            ),
            "der",
            backend
        )
        assert cert.not_before == datetime.datetime(2010, 1, 1, 8, 30)
        assert cert.not_after == datetime.datetime(2050, 1, 1, 12, 1)
        assert cert.version == x509.X509Version.v3

    def test_invalid_version_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "invalid_version.pem"),
            "pem",
            backend
        )
        with pytest.raises(x509.InvalidX509Version):
            cert.version

    def test_version_1_cert(self, backend):
        cert = _load_cert(
            os.path.join("x509", "v1_cert.pem"),
            "pem",
            backend
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
        cert = _load_cert(
            os.path.join("x509", "custom", "dsa_root.pem"),
            "pem",
            backend
        )
        public_key = cert.public_key()
        assert isinstance(public_key, interfaces.DSAPublicKey)


@pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestECDSAX509Certificate(object):
    def test_load_ecdsa_cert(self, backend):
        _skip_curve_unsupported(backend, ec.SECP384R1())
        cert = _load_cert(
            os.path.join("x509", "ecdsa_root.pem"),
            "pem",
            backend
        )
        public_key = cert.public_key()
        assert isinstance(public_key, interfaces.EllipticCurvePublicKey)
