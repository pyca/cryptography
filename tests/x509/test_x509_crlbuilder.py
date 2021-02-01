# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import datetime

import pytest

import pytz

from cryptography import x509
from cryptography.hazmat.backends.interfaces import (
    DSABackend,
    EllipticCurveBackend,
    RSABackend,
    X509Backend,
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448
from cryptography.x509.oid import (
    AuthorityInformationAccessOID,
    NameOID,
    SignatureAlgorithmOID,
)

from ..hazmat.primitives.fixtures_dsa import DSA_KEY_2048
from ..hazmat.primitives.fixtures_ec import EC_KEY_SECP256R1
from ..hazmat.primitives.fixtures_rsa import RSA_KEY_2048, RSA_KEY_512
from ..hazmat.primitives.test_ec import _skip_curve_unsupported


class TestCertificateRevocationListBuilder(object):
    def test_issuer_name_invalid(self):
        builder = x509.CertificateRevocationListBuilder()
        with pytest.raises(TypeError):
            builder.issuer_name("notanx509name")  # type:ignore[arg-type]

    def test_set_issuer_name_twice(self):
        builder = x509.CertificateRevocationListBuilder().issuer_name(
            x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US")])
        )
        with pytest.raises(ValueError):
            builder.issuer_name(
                x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US")])
            )

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_aware_last_update(self, backend):
        last_time = datetime.datetime(2012, 1, 16, 22, 43)
        tz = pytz.timezone("US/Pacific")
        last_time = tz.localize(last_time)
        utc_last = datetime.datetime(2012, 1, 17, 6, 43)
        next_time = datetime.datetime(2022, 1, 17, 6, 43)
        private_key = RSA_KEY_2048.private_key(backend)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_time)
            .next_update(next_time)
        )

        crl = builder.sign(private_key, hashes.SHA256(), backend)
        assert crl.last_update == utc_last

    def test_last_update_invalid(self):
        builder = x509.CertificateRevocationListBuilder()
        with pytest.raises(TypeError):
            builder.last_update("notadatetime")  # type:ignore[arg-type]

    def test_last_update_before_1950(self):
        builder = x509.CertificateRevocationListBuilder()
        with pytest.raises(ValueError):
            builder.last_update(datetime.datetime(1940, 8, 10))

    def test_set_last_update_twice(self):
        builder = x509.CertificateRevocationListBuilder().last_update(
            datetime.datetime(2002, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.last_update(datetime.datetime(2002, 1, 1, 12, 1))

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_aware_next_update(self, backend):
        next_time = datetime.datetime(2022, 1, 16, 22, 43)
        tz = pytz.timezone("US/Pacific")
        next_time = tz.localize(next_time)
        utc_next = datetime.datetime(2022, 1, 17, 6, 43)
        last_time = datetime.datetime(2012, 1, 17, 6, 43)
        private_key = RSA_KEY_2048.private_key(backend)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_time)
            .next_update(next_time)
        )

        crl = builder.sign(private_key, hashes.SHA256(), backend)
        assert crl.next_update == utc_next

    def test_next_update_invalid(self):
        builder = x509.CertificateRevocationListBuilder()
        with pytest.raises(TypeError):
            builder.next_update("notadatetime")  # type:ignore[arg-type]

    def test_next_update_before_1950(self):
        builder = x509.CertificateRevocationListBuilder()
        with pytest.raises(ValueError):
            builder.next_update(datetime.datetime(1940, 8, 10))

    def test_set_next_update_twice(self):
        builder = x509.CertificateRevocationListBuilder().next_update(
            datetime.datetime(2002, 1, 1, 12, 1)
        )
        with pytest.raises(ValueError):
            builder.next_update(datetime.datetime(2002, 1, 1, 12, 1))

    def test_last_update_after_next_update(self):
        builder = x509.CertificateRevocationListBuilder()

        builder = builder.next_update(datetime.datetime(2002, 1, 1, 12, 1))
        with pytest.raises(ValueError):
            builder.last_update(datetime.datetime(2003, 1, 1, 12, 1))

    def test_next_update_after_last_update(self):
        builder = x509.CertificateRevocationListBuilder()

        builder = builder.last_update(datetime.datetime(2002, 1, 1, 12, 1))
        with pytest.raises(ValueError):
            builder.next_update(datetime.datetime(2001, 1, 1, 12, 1))

    def test_add_extension_checks_for_duplicates(self):
        builder = x509.CertificateRevocationListBuilder().add_extension(
            x509.CRLNumber(1), False
        )

        with pytest.raises(ValueError):
            builder.add_extension(x509.CRLNumber(2), False)

    def test_add_invalid_extension(self):
        builder = x509.CertificateRevocationListBuilder()

        with pytest.raises(TypeError):
            builder.add_extension(object(), False)  # type:ignore[arg-type]

    def test_add_invalid_revoked_certificate(self):
        builder = x509.CertificateRevocationListBuilder()

        with pytest.raises(TypeError):
            builder.add_revoked_certificate(object())  # type:ignore[arg-type]

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_issuer_name(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = (
            x509.CertificateRevocationListBuilder()
            .last_update(datetime.datetime(2002, 1, 1, 12, 1))
            .next_update(datetime.datetime(2030, 1, 1, 12, 1))
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_last_update(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US")])
            )
            .next_update(datetime.datetime(2030, 1, 1, 12, 1))
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_no_next_update(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US")])
            )
            .last_update(datetime.datetime(2030, 1, 1, 12, 1))
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_empty_list(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
        )

        crl = builder.sign(private_key, hashes.SHA256(), backend)
        assert len(crl) == 0
        assert crl.last_update == last_update
        assert crl.next_update == next_update

    @pytest.mark.parametrize(
        "extension",
        [
            x509.CRLNumber(13),
            x509.DeltaCRLIndicator(12345678901234567890),
            x509.AuthorityKeyIdentifier(
                b"\xc3\x9c\xf3\xfc\xd3F\x084\xbb\xceF\x7f\xa0|[\xf3\xe2\x08"
                b"\xcbY",
                None,
                None,
            ),
            x509.AuthorityInformationAccess(
                [
                    x509.AccessDescription(
                        AuthorityInformationAccessOID.CA_ISSUERS,
                        x509.DNSName("cryptography.io"),
                    )
                ]
            ),
            x509.IssuerAlternativeName(
                [x509.UniformResourceIdentifier("https://cryptography.io")]
            ),
        ],
    )
    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_extensions(self, backend, extension):
        private_key = RSA_KEY_2048.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
            .add_extension(extension, False)
        )

        crl = builder.sign(private_key, hashes.SHA256(), backend)
        assert len(crl) == 0
        assert len(crl.extensions) == 1
        ext = crl.extensions.get_extension_for_class(type(extension))
        assert ext.critical is False
        assert ext.value == extension

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_multiple_extensions_critical(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        ian = x509.IssuerAlternativeName(
            [x509.UniformResourceIdentifier("https://cryptography.io")]
        )
        crl_number = x509.CRLNumber(13)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
            .add_extension(crl_number, False)
            .add_extension(ian, True)
        )

        crl = builder.sign(private_key, hashes.SHA256(), backend)
        assert len(crl) == 0
        assert len(crl.extensions) == 2
        ext1 = crl.extensions.get_extension_for_class(x509.CRLNumber)
        assert ext1.critical is False
        assert ext1.value == crl_number
        ext2 = crl.extensions.get_extension_for_class(
            x509.IssuerAlternativeName
        )
        assert ext2.critical is True
        assert ext2.value == ian

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_freshestcrl_extension(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        freshest = x509.FreshestCRL(
            [
                x509.DistributionPoint(
                    [x509.UniformResourceIdentifier("http://d.om/delta")],
                    None,
                    None,
                    None,
                )
            ]
        )
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
            .add_extension(freshest, False)
        )

        crl = builder.sign(private_key, hashes.SHA256(), backend)
        assert len(crl) == 0
        assert len(crl.extensions) == 1
        ext1 = crl.extensions.get_extension_for_class(x509.FreshestCRL)
        assert ext1.critical is False
        assert isinstance(ext1.value[0], x509.DistributionPoint)
        uri = ext1.value[0].full_name[0]
        assert isinstance(uri, x509.UniformResourceIdentifier)
        assert uri.value == "http://d.om/delta"

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_add_unsupported_extension(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
            .add_extension(x509.OCSPNoCheck(), False)
        )
        with pytest.raises(NotImplementedError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_rsa_key_too_small(self, backend):
        private_key = RSA_KEY_512.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA512(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_with_invalid_hash(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
        )

        with pytest.raises(TypeError):
            builder.sign(private_key, object(), backend)

    @pytest.mark.supported(
        only_if=lambda backend: backend.ed25519_supported(),
        skip_message="Requires OpenSSL with Ed25519 support",
    )
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_with_invalid_hash_ed25519(self, backend):
        private_key = ed25519.Ed25519PrivateKey.generate()
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, object(), backend)
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.supported(
        only_if=lambda backend: backend.ed448_supported(),
        skip_message="Requires OpenSSL with Ed448 support",
    )
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_with_invalid_hash_ed448(self, backend):
        private_key = ed448.Ed448PrivateKey.generate()
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, object(), backend)
        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.SHA256(), backend)

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_dsa_key(self, backend):
        private_key = DSA_KEY_2048.private_key(backend)
        invalidity_date = x509.InvalidityDate(
            datetime.datetime(2002, 1, 1, 0, 0)
        )
        ian = x509.IssuerAlternativeName(
            [x509.UniformResourceIdentifier("https://cryptography.io")]
        )
        revoked_cert0 = (
            x509.RevokedCertificateBuilder()
            .serial_number(2)
            .revocation_date(datetime.datetime(2012, 1, 1, 1, 1))
            .add_extension(invalidity_date, False)
            .build(backend)
        )
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
            .add_revoked_certificate(revoked_cert0)
            .add_extension(ian, False)
        )

        crl = builder.sign(private_key, hashes.SHA256(), backend)
        assert (
            crl.extensions.get_extension_for_class(
                x509.IssuerAlternativeName
            ).value
            == ian
        )
        assert crl[0].serial_number == revoked_cert0.serial_number
        assert crl[0].revocation_date == revoked_cert0.revocation_date
        assert len(crl[0].extensions) == 1
        ext = crl[0].extensions.get_extension_for_class(x509.InvalidityDate)
        assert ext.critical is False
        assert ext.value == invalidity_date

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_ec_key(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        private_key = ec.generate_private_key(ec.SECP256R1(), backend)
        invalidity_date = x509.InvalidityDate(
            datetime.datetime(2002, 1, 1, 0, 0)
        )
        ian = x509.IssuerAlternativeName(
            [x509.UniformResourceIdentifier("https://cryptography.io")]
        )
        revoked_cert0 = (
            x509.RevokedCertificateBuilder()
            .serial_number(2)
            .revocation_date(datetime.datetime(2012, 1, 1, 1, 1))
            .add_extension(invalidity_date, False)
            .build(backend)
        )
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
            .add_revoked_certificate(revoked_cert0)
            .add_extension(ian, False)
        )

        crl = builder.sign(private_key, hashes.SHA256(), backend)
        assert (
            crl.extensions.get_extension_for_class(
                x509.IssuerAlternativeName
            ).value
            == ian
        )
        assert crl[0].serial_number == revoked_cert0.serial_number
        assert crl[0].revocation_date == revoked_cert0.revocation_date
        assert len(crl[0].extensions) == 1
        ext = crl[0].extensions.get_extension_for_class(x509.InvalidityDate)
        assert ext.critical is False
        assert ext.value == invalidity_date

    @pytest.mark.supported(
        only_if=lambda backend: backend.ed25519_supported(),
        skip_message="Requires OpenSSL with Ed25519 support",
    )
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_ed25519_key(self, backend):
        private_key = ed25519.Ed25519PrivateKey.generate()
        invalidity_date = x509.InvalidityDate(
            datetime.datetime(2002, 1, 1, 0, 0)
        )
        ian = x509.IssuerAlternativeName(
            [x509.UniformResourceIdentifier("https://cryptography.io")]
        )
        revoked_cert0 = (
            x509.RevokedCertificateBuilder()
            .serial_number(2)
            .revocation_date(datetime.datetime(2012, 1, 1, 1, 1))
            .add_extension(invalidity_date, False)
            .build(backend)
        )
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
            .add_revoked_certificate(revoked_cert0)
            .add_extension(ian, False)
        )

        crl = builder.sign(private_key, None, backend)
        assert crl.signature_hash_algorithm is None
        assert crl.signature_algorithm_oid == SignatureAlgorithmOID.ED25519
        assert (
            crl.extensions.get_extension_for_class(
                x509.IssuerAlternativeName
            ).value
            == ian
        )
        assert crl[0].serial_number == revoked_cert0.serial_number
        assert crl[0].revocation_date == revoked_cert0.revocation_date
        assert len(crl[0].extensions) == 1
        ext = crl[0].extensions.get_extension_for_class(x509.InvalidityDate)
        assert ext.critical is False
        assert ext.value == invalidity_date

    @pytest.mark.supported(
        only_if=lambda backend: backend.ed448_supported(),
        skip_message="Requires OpenSSL with Ed448 support",
    )
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_ed448_key(self, backend):
        private_key = ed448.Ed448PrivateKey.generate()
        invalidity_date = x509.InvalidityDate(
            datetime.datetime(2002, 1, 1, 0, 0)
        )
        ian = x509.IssuerAlternativeName(
            [x509.UniformResourceIdentifier("https://cryptography.io")]
        )
        revoked_cert0 = (
            x509.RevokedCertificateBuilder()
            .serial_number(2)
            .revocation_date(datetime.datetime(2012, 1, 1, 1, 1))
            .add_extension(invalidity_date, False)
            .build(backend)
        )
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
            .add_revoked_certificate(revoked_cert0)
            .add_extension(ian, False)
        )

        crl = builder.sign(private_key, None, backend)
        assert crl.signature_hash_algorithm is None
        assert crl.signature_algorithm_oid == SignatureAlgorithmOID.ED448
        assert (
            crl.extensions.get_extension_for_class(
                x509.IssuerAlternativeName
            ).value
            == ian
        )
        assert crl[0].serial_number == revoked_cert0.serial_number
        assert crl[0].revocation_date == revoked_cert0.revocation_date
        assert len(crl[0].extensions) == 1
        ext = crl[0].extensions.get_extension_for_class(x509.InvalidityDate)
        assert ext.critical is False
        assert ext.value == invalidity_date

    @pytest.mark.requires_backend_interface(interface=DSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_dsa_key_sign_md5(self, backend):
        private_key = DSA_KEY_2048.private_key(backend)
        last_time = datetime.datetime(2012, 1, 16, 22, 43)
        next_time = datetime.datetime(2022, 1, 17, 6, 43)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_time)
            .next_update(next_time)
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.MD5(), backend)

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_ec_key_sign_md5(self, backend):
        _skip_curve_unsupported(backend, ec.SECP256R1())
        private_key = EC_KEY_SECP256R1.private_key(backend)
        last_time = datetime.datetime(2012, 1, 16, 22, 43)
        next_time = datetime.datetime(2022, 1, 17, 6, 43)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_time)
            .next_update(next_time)
        )

        with pytest.raises(ValueError):
            builder.sign(private_key, hashes.MD5(), backend)

    @pytest.mark.requires_backend_interface(interface=RSABackend)
    @pytest.mark.requires_backend_interface(interface=X509Backend)
    def test_sign_with_revoked_certificates(self, backend):
        private_key = RSA_KEY_2048.private_key(backend)
        last_update = datetime.datetime(2002, 1, 1, 12, 1)
        next_update = datetime.datetime(2030, 1, 1, 12, 1)
        invalidity_date = x509.InvalidityDate(
            datetime.datetime(2002, 1, 1, 0, 0)
        )
        revoked_cert0 = (
            x509.RevokedCertificateBuilder()
            .serial_number(38)
            .revocation_date(datetime.datetime(2011, 1, 1, 1, 1))
            .build(backend)
        )
        revoked_cert1 = (
            x509.RevokedCertificateBuilder()
            .serial_number(2)
            .revocation_date(datetime.datetime(2012, 1, 1, 1, 1))
            .add_extension(invalidity_date, False)
            .build(backend)
        )
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(
                x509.Name(
                    [
                        x509.NameAttribute(
                            NameOID.COMMON_NAME, "cryptography.io CA"
                        )
                    ]
                )
            )
            .last_update(last_update)
            .next_update(next_update)
            .add_revoked_certificate(revoked_cert0)
            .add_revoked_certificate(revoked_cert1)
        )

        crl = builder.sign(private_key, hashes.SHA256(), backend)
        assert len(crl) == 2
        assert crl.last_update == last_update
        assert crl.next_update == next_update
        assert crl[0].serial_number == revoked_cert0.serial_number
        assert crl[0].revocation_date == revoked_cert0.revocation_date
        assert len(crl[0].extensions) == 0
        assert crl[1].serial_number == revoked_cert1.serial_number
        assert crl[1].revocation_date == revoked_cert1.revocation_date
        assert len(crl[1].extensions) == 1
        ext = crl[1].extensions.get_extension_for_class(x509.InvalidityDate)
        assert ext.critical is False
        assert ext.value == invalidity_date
