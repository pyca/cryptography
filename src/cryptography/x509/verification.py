# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509 import Certificate
from cryptography.x509.oid import ExtensionOID


class InvalidCertificate(Exception):
    pass


class InvalidSigningCertificate(Exception):
    pass


def _can_sign_certificates(certificate):
    basic_constraints = certificate.extensions.get_extension_for_oid(
        ExtensionOID.BASIC_CONSTRAINTS).value
    key_usage = certificate.extensions.get_extension_for_oid(
        ExtensionOID.KEY_USAGE).value

    if not basic_constraints.ca:
        raise InvalidSigningCertificate(
            "The certificate is not marked as a CA in its BasicConstraints "
            "extension."
        )
    elif not key_usage.key_cert_sign:
        raise InvalidSigningCertificate(
            "The certificate public key is not marked for verifying "
            "certificates in its KeyUsage extension."
        )
    else:
        return True


def _is_issuing_certificate(issuing_certificate, issued_certificate):
        return (issuing_certificate.subject == issued_certificate.issuer)


class CertificateVerificationContext(object):
    def __init__(self, certificate):
        if not isinstance(certificate, Certificate):
            raise InvalidCertificate(
                "The signing certificate must be a Certificate."
            )
        _can_sign_certificates(certificate)

        self._signing_cert = certificate

    def update(self, certificate):
        """
        Processes the provided certificate. Raises an exception if the
        certificate is invalid.
        """
        if not isinstance(certificate, Certificate):
            raise InvalidCertificate(
                "The signed certificate must be a Certificate."
            )

        self._signed_cert = certificate

    def verify(self):
        """
        Verifies the signature of the certificate provided to update against
        the certificate associated with the context. Raises an exception if
        the verification process fails.
        """
        if not _is_issuing_certificate(self._signing_cert, self._signed_cert):
            raise InvalidCertificate(
                "The certificate issuer does not match the subject name of "
                "the context certificate."
            )

        signature_hash_algorithm = self._signed_cert.signature_hash_algorithm
        signature_bytes = self._signed_cert.signature
        signer_public_key = self._signing_cert.public_key()

        if isinstance(signer_public_key, rsa.RSAPublicKey):
            verifier = signer_public_key.verifier(
                signature_bytes, padding.PKCS1v15(), signature_hash_algorithm)
        elif isinstance(signer_public_key, ec.EllipticCurvePublicKey):
            verifier = signer_public_key.verifier(
                signature_bytes, ec.ECDSA(signature_hash_algorithm))
        else:
            verifier = signer_public_key.verifier(
                signature_bytes, signature_hash_algorithm)

        verifier.update(self._signed_cert.tbs_certificate_bytes)
        verifier.verify()
