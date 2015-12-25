# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import datetime

import pytest

from cryptography import x509
from cryptography.hazmat.backends.interfaces import (
    DSABackend, EllipticCurveBackend, RSABackend, X509Backend
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from .hazmat.primitives.fixtures_dsa import DSA_KEY_2048
from .hazmat.primitives.fixtures_rsa import RSA_KEY_2048, RSA_KEY_512
from .hazmat.primitives.test_ec import _skip_curve_unsupported


class TestCertificateRevocationListBuilder(object):
    def test_issuer_name_invalid(self):
        builder = x509.CertificateRevocationListBuilder()
        with pytest.raises(TypeError):
            builder.issuer_name("notanx509name")

    def test_set_issuer_name_twice(self):
        builder = x509.CertificateRevocationListBuilder().issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        )
        with pytest.raises(ValueError):
            builder.issuer_name(
                x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
            )

    def test_last_update_invalid(self):
        builder = x509.CertificateRevocationListBuilder()
        with pytest.raises(TypeError):
            builder.last_update("notadatetime")

    def test_last_update_before_unix_epoch(self):
        builder = x509.CertificateRevocationListBuilder()
        with pytest.raises(ValueError):
            builder.last_update(datetime.datetime(1960, 8, 10))

    def test_set_last_update_twice(self):
        builder = x509.CertificateRevocationListBuilder().last_update(
            datetime.datetime(2002, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.last_update(datetime.datetime(2002, 1, 1, 12, 1))

    def test_next_update_invalid(self):
        builder = x509.CertificateRevocationListBuilder()
        with pytest.raises(TypeError):
            builder.next_update("notadatetime")

    def test_next_update_before_unix_epoch(self):
        builder = x509.CertificateRevocationListBuilder()
        with pytest.raises(ValueError):
            builder.next_update(datetime.datetime(1960, 8, 10))

    def test_set_next_update_twice(self):
        builder = x509.CertificateRevocationListBuilder().next_update(
            datetime.datetime(2002, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.next_update(datetime.datetime(2002, 1, 1, 12, 1))

    def test_last_update_after_next_update(self):
        builder = x509.CertificateRevocationListBuilder()

        builder = builder.next_update(
            datetime.datetime(2002, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.last_update(datetime.datetime(2003, 1, 1, 12, 1))

    def test_next_update_after_last_update(self):
        builder = x509.CertificateRevocationListBuilder()

        builder = builder.last_update(
            datetime.datetime(2002, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.next_update(datetime.datetime(2001, 1, 1, 12, 1))

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_issuer_name(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateRevocationListBuilder().last_update(
            datetime.datetime(2002, 1, 1, 12, 1)
        ).next_update(
            datetime.datetime(2030, 1, 1, 12, 1)
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_last_update(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateRevocationListBuilder().issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).next_update(
            datetime.datetime(2030, 1, 1, 12, 1)
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_next_update(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = x509.CertificateRevocationListBuilder().issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, u'US')])
        ).last_update(
            datetime.datetime(2030, 1, 1, 12, 1)
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_empty_list(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = x509.CertificateRevocationListBuilder().issuer_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"cryptography.io CA")
            ])
        ).last_update(last_update).next_update(next_update)

        crl = builder.sign(private_key, hashes.SHA256(), backend)
        assert len(crl) == 0
        assert crl.last_update == last_update
        assert crl.next_update == next_update

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_rsa_key_too_small(self, backend):
        private_key = RSA_KEY_512.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = x509.CertificateRevocationListBuilder().issuer_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"cryptography.io CA")
            ])
        ).last_update(
            last_update
        ).next_update(
            next_update
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA512(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_with_invalid_hash(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = x509.CertificateRevocationListBuilder().issuer_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"cryptography.io CA")
            ])
        ).last_update(
            last_update
        ).next_update(
            next_update
        )

        with pytest.raises(TypeError):
            builder.sign(private_key, object(), backend)

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_dsa_key_unsupported(self, backend):
        private_key = DSA_KEY_2048.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = x509.CertificateRevocationListBuilder().issuer_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"cryptography.io CA")
            ])
        ).last_update(
            last_update
        ).next_update(
            next_update
        )

        with pytest.raises(NotImplementedError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_ec_key_unsupported(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = x509.CertificateRevocationListBuilder().issuer_name(
            x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, u"cryptography.io CA")
            ])
        ).last_update(
            last_update
        ).next_update(
            next_update
        )

        with pytest.raises(NotImplementedError):
            builder.sign(private_key, hashes.SHA256(), backend)
