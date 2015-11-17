# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import datetime
import os

import pytest

from cryptography import x509
from cryptography.exceptions import InvalidSignature

from cryptography.hazmat.backends.interfaces import (
    EllipticCurveBackend, X509Backend
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec

from cryptography.x509 import oid
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.verification import (
    CertificateVerificationContext, InvalidCertificate,
    InvalidSigningCertificate
)

from .hazmat.primitives import fixtures_dsa, fixtures_ec, fixtures_rsa

from .hazmat.primitives.test_ec import _skip_curve_unsupported
from .test_x509 import _load_cert


def build_subjects(common_names):
    subjects = []
    for common_name in common_names:
        subject = x509.Name([
            x509.NameAttribute(oid.NameOID.COUNTRY_NAME, u'US'),
            x509.NameAttribute(oid.NameOID.STATE_OR_PROVINCE_NAME, u'State'),
            x509.NameAttribute(oid.NameOID.LOCALITY_NAME, u'Locality'),
            x509.NameAttribute(oid.NameOID.ORGANIZATION_NAME, u'Org'),
            x509.NameAttribute(oid.NameOID.COMMON_NAME, common_name)]
        )
        subjects.append(subject)
    return subjects


def build_certificate_chain(names, not_valid_before, not_valid_after,
                            keys, extension_lists, hash_algorithm, backend,
                            serial_number):
    subjects = build_subjects(names)
    not_valid_befores = [not_valid_before] * len(subjects)
    not_valid_afters = [not_valid_after] * len(subjects)

    certificate_chain = []
    private_key = keys[0].private_key(backend)
    certificate_chain.append(
        build_certificate(
            subjects[0], subjects[0], not_valid_befores[0],
            not_valid_afters[0], private_key, private_key.public_key(),
            extension_lists[0], hash_algorithm, backend, serial_number
        )
    )

    for i in range(1, len(subjects)):
        private_key = keys[i - 1].private_key(backend)
        public_key = keys[i].private_key(backend).public_key()
        certificate_chain.append(
            build_certificate(
                subjects[i], subjects[i - 1], not_valid_befores[i],
                not_valid_afters[i], private_key, public_key,
                extension_lists[i], hash_algorithm, backend, serial_number
            )
        )

    return certificate_chain


def build_certificate(subject, issuer, not_valid_before, not_valid_after,
                      signing_key, public_key, extensions, hash_alg, backend,
                      serial_number):
    builder = x509.CertificateBuilder().serial_number(
        serial_number
    ).issuer_name(
        issuer
    ).subject_name(
        subject
    ).public_key(
        public_key
    ).not_valid_before(
        not_valid_before
    ).not_valid_after(
        not_valid_after
    )

    for ext in extensions:
        builder = builder.add_extension(
            ext.get('extension'), ext.get('critical')
        )
    return builder.sign(signing_key, hash_alg, backend)


def build_extensions(cas, path_lengths, key_cert_signs, num_extension_sets):
    extension_lists = []
    for i in range(num_extension_sets):
        extension_list = [
            {
                'extension': x509.BasicConstraints(
                    cas[i], path_lengths[i]
                ),
                'critical': True
            },
            {
                'extension': x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=key_cert_signs[i],
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False
                ),
                'critical': True
            }
        ]
        extension_lists.append(extension_list)

    return extension_lists


def _skip_backend_if_key_unsupported(key, backend):
    private_key = key.private_key(backend)
    if isinstance(
        private_key, (dsa.DSAPrivateKey, ec.EllipticCurvePrivateKey)
    ):
        if backend._lib.OPENSSL_VERSION_NUMBER <= 0x10001000:
            pytest.skip("Requires a newer OpenSSL. Must be > 1.0.1")


@pytest.mark.requires_backend_interface(interface=X509Backend)
class TestCertificateVerificationContext(object):

    def test_init(self, backend):
        trusted_cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs", "pathLenConstraint6CACert.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )
        CertificateVerificationContext(trusted_cert)

    def test_init_fail_not_a_cert(self, backend):
        with pytest.raises(InvalidCertificate):
            CertificateVerificationContext("invalid")

    def test_init_fail_cert_missing_extension(self, backend):
        cert = _load_cert(
            os.path.join("x509", "custom", "dsa_selfsigned_ca.pem"),
            x509.load_pem_x509_certificate,
            backend
        )

        with pytest.raises(ExtensionNotFound):
            CertificateVerificationContext(cert)

    def test_init_fail_cert_with_ca_false(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "custom", "all_supported_names.pem"
            ),
            x509.load_pem_x509_certificate,
            backend
        )

        with pytest.raises(InvalidSigningCertificate):
            CertificateVerificationContext(cert)

    def test_init_fail_cert_with_key_cert_sign_false(self, backend):
        cert = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs",
                "keyUsageNotCriticalkeyCertSignFalseCACert.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )

        with pytest.raises(InvalidSigningCertificate):
            CertificateVerificationContext(cert)

    def test_update(self, backend):
        certificate = _load_cert(
            os.path.join(
                "x509", "PKITS_data", "certs", "pathLenConstraint6CACert.crt"
            ),
            x509.load_der_x509_certificate,
            backend
        )

        # Update with a valid certificate.
        verifier = CertificateVerificationContext(certificate)
        verifier.update(certificate)
        assert verifier._signed_cert == certificate

        # Update with an invalid certificate.
        with pytest.raises(InvalidCertificate):
            verifier.update("invalid")

    def _test_verify(self, keys, backend):
        for key in keys:
            _skip_backend_if_key_unsupported(key, backend)

        names = [u'a.com', u'b.com']
        not_valid_before = datetime.datetime(2002, 1, 1, 12, 1)
        not_valid_after = datetime.datetime(2030, 12, 31, 8, 30)
        serial_number = 77
        extension_lists = build_extensions(
            [True, True], [0, 0], [True, True], len(names)
        )

        cert_chain = build_certificate_chain(
            names, not_valid_before, not_valid_after, keys, extension_lists,
            hashes.SHA1(), backend, serial_number
        )

        # Test a valid call.
        verifier = CertificateVerificationContext(cert_chain[0])
        verifier.update(cert_chain[1])
        verifier.verify()

        # Test an invalid call.
        verifier = CertificateVerificationContext(cert_chain[1])
        verifier.update(cert_chain[0])

        with pytest.raises(InvalidCertificate):
            verifier.verify()

        # Test an invalid call with valid subject/issuer names.
        keys.reverse()
        alt_cert_chain = build_certificate_chain(
            names, not_valid_before, not_valid_after, keys, extension_lists,
            hashes.SHA1(), backend, serial_number
        )
        verifier = CertificateVerificationContext(cert_chain[0])
        verifier.update(alt_cert_chain[1])

        with pytest.raises(InvalidSignature):
            verifier.verify()

    @pytest.mark.parametrize(
        ("keys"),
        [
            (
                [
                    fixtures_rsa.RSA_KEY_512,
                    fixtures_rsa.RSA_KEY_1024,
                ]
            ),
            (
                [
                    fixtures_dsa.DSA_KEY_1024,
                    fixtures_dsa.DSA_KEY_2048,
                ]
            ),
        ]
    )
    def test_verify(self, keys, backend):
        self._test_verify(keys, backend)

    @pytest.mark.requires_backend_interface(interface=EllipticCurveBackend)
    def test_verify_with_elliptic_curves(self, backend):
        keys = [fixtures_ec.EC_KEY_SECP192R1, fixtures_ec.EC_KEY_SECT163K1]
        for key in keys:
            _skip_curve_unsupported(backend, key.public_numbers.curve)
        self._test_verify(keys, backend)
