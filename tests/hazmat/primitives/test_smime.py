# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import re

import pytest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization, smime
from cryptography.hazmat.primitives.asymmetric import ed25519

from .utils import load_vectors_from_file


def _load_cert_key():
    key = load_vectors_from_file(
        os.path.join("x509", "custom", "ca", "ca_key.pem"),
        lambda pemfile: serialization.load_pem_private_key(
            pemfile.read(), None
        ),
        mode="rb",
    )
    cert = load_vectors_from_file(
        os.path.join("x509", "custom", "ca", "ca.pem"),
        loader=lambda pemfile: x509.load_pem_x509_certificate(pemfile.read()),
        mode="rb",
    )
    return cert, key


class TestSMIMEBuilder(object):
    def test_invalid_data(self):
        builder = smime.SMIMESignatureBuilder()
        with pytest.raises(TypeError):
            builder.add_data(u"not bytes")

    def test_add_data_twice(self):
        builder = smime.SMIMESignatureBuilder().add_data(b"test")
        with pytest.raises(ValueError):
            builder.add_data(b"test")

    def test_sign_no_signer(self):
        builder = smime.SMIMESignatureBuilder().add_data(b"test")
        with pytest.raises(ValueError):
            builder.sign(serialization.Encoding.PEM, [])

    def test_sign_no_data(self):
        cert, key = _load_cert_key()
        builder = smime.SMIMESignatureBuilder().add_signer(
            cert, key, hashes.SHA256()
        )
        with pytest.raises(ValueError):
            builder.sign(serialization.Encoding.PEM, [])

    def test_unsupported_hash_alg(self):
        cert, key = _load_cert_key()
        with pytest.raises(TypeError):
            smime.SMIMESignatureBuilder().add_signer(
                cert, key, hashes.SHA512_256()
            )

    def test_not_a_cert(self):
        cert, key = _load_cert_key()
        with pytest.raises(TypeError):
            smime.SMIMESignatureBuilder().add_signer(
                b"notacert", key, hashes.SHA256()
            )

    @pytest.mark.supported(
        only_if=lambda backend: backend.ed25519_supported(),
        skip_message="Does not support ed25519.",
    )
    def test_unsupported_key_type(self):
        cert, _ = _load_cert_key()
        key = ed25519.Ed25519PrivateKey.generate()
        with pytest.raises(TypeError):
            smime.SMIMESignatureBuilder().add_signer(
                cert, key, hashes.SHA256()
            )

    def test_sign_invalid_options(self):
        cert, key = _load_cert_key()
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(b"test")
            .add_signer(cert, key, hashes.SHA256())
        )
        with pytest.raises(ValueError):
            builder.sign(serialization.Encoding.PEM, [b"invalid"])

    def test_sign_invalid_encoding(self):
        cert, key = _load_cert_key()
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(b"test")
            .add_signer(cert, key, hashes.SHA256())
        )
        with pytest.raises(ValueError):
            builder.sign(serialization.Encoding.Raw, [])

    def test_sign_invalid_options_text_no_detached(self):
        cert, key = _load_cert_key()
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(b"test")
            .add_signer(cert, key, hashes.SHA256())
        )
        options = [smime.SMIMEOptions.Text]
        with pytest.raises(ValueError):
            builder.sign(serialization.Encoding.PEM, options)

    def test_sign_invalid_options_no_attrs_and_no_caps(self):
        cert, key = _load_cert_key()
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(b"test")
            .add_signer(cert, key, hashes.SHA256())
        )
        options = [
            smime.SMIMEOptions.NoAttributes,
            smime.SMIMEOptions.NoCapabilities,
        ]
        with pytest.raises(ValueError):
            builder.sign(serialization.Encoding.PEM, options)

    def test_smime_sign_detached(self):
        data = b"hello world"
        cert, key = _load_cert_key()
        options = [smime.SMIMEOptions.DetachedSignature]
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(data)
            .add_signer(cert, key, hashes.SHA256())
        )

        sig = builder.sign(serialization.Encoding.PEM, options)
        sig_binary = builder.sign(serialization.Encoding.DER, options)
        # We don't have a generic ASN.1 parser available to us so we instead
        # will assert on specific byte sequences being present based on the
        # parameters chosen above.
        assert b"sha-256" in sig
        # Detached signature means that the signed data is *not* embedded into
        # the PKCS7 structure itself, but is present in the PEM serialization
        # as a separate section before the PKCS7 data. So we should expect to
        # have data in sig but not in sig_binary
        assert data in sig
        assert data not in sig_binary
        # TODO: validate sig

    def test_sign_byteslike(self):
        data = bytearray(b"hello world")
        cert, key = _load_cert_key()
        options = [smime.SMIMEOptions.DetachedSignature]
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(data)
            .add_signer(cert, key, hashes.SHA256())
        )

        sig = builder.sign(serialization.Encoding.PEM, options)
        assert data in sig

    @pytest.mark.parametrize(
        ("hash_alg", "expected_value"),
        [
            (hashes.SHA1(), b"\x06\x05+\x0e\x03\x02\x1a"),
            (hashes.SHA256(), b"\x06\t`\x86H\x01e\x03\x04\x02\x01"),
            (hashes.SHA384(), b"\x06\t`\x86H\x01e\x03\x04\x02\x02"),
            (hashes.SHA512(), b"\x06\t`\x86H\x01e\x03\x04\x02\x03"),
        ],
    )
    def test_smime_sign_alternate_digests_der(self, hash_alg, expected_value):
        data = b"hello world"
        cert, key = _load_cert_key()
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(data)
            .add_signer(cert, key, hash_alg)
        )

        sig = builder.sign(serialization.Encoding.DER, [])
        # When in detached signature mode the hash algorithm is stored as a
        # byte string like "sha-384".
        assert expected_value in sig

    @pytest.mark.parametrize(
        ("hash_alg", "expected_value"),
        [
            (hashes.SHA1(), b"sha1"),
            (hashes.SHA256(), b"sha-256"),
            (hashes.SHA384(), b"sha-384"),
            (hashes.SHA512(), b"sha-512"),
        ],
    )
    def test_smime_sign_alternate_digests_detached_pem(
        self, hash_alg, expected_value
    ):
        data = b"hello world"
        cert, key = _load_cert_key()
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(data)
            .add_signer(cert, key, hash_alg)
        )
        options = [smime.SMIMEOptions.DetachedSignature]
        sig = builder.sign(serialization.Encoding.PEM, options)
        # When in detached signature mode the hash algorithm is stored as a
        # byte string like "sha-384".
        assert expected_value in sig

    def test_smime_sign_attached(self):
        data = b"hello world"
        cert, key = _load_cert_key()
        options = []
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(data)
            .add_signer(cert, key, hashes.SHA256())
        )

        sig_binary = builder.sign(serialization.Encoding.DER, options)
        # When not passing detached signature the signed data is embedded into
        # the PKCS7 structure itself
        assert data in sig_binary
        # TODO: validate sig

    def test_smime_sign_binary(self):
        data = b"hello\nworld"
        cert, key = _load_cert_key()
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(data)
            .add_signer(cert, key, hashes.SHA256())
        )

        sig_no_binary = builder.sign(serialization.Encoding.DER, [])
        sig_binary = builder.sign(
            serialization.Encoding.DER, [smime.SMIMEOptions.Binary]
        )
        # Binary prevents translation of LF to CR+LF (SMIME canonical form)
        # so data should not be present in sig_no_binary, but should be present
        # in sig_binary
        assert data not in sig_no_binary
        assert data in sig_binary
        # TODO: validate sig

    def test_smime_sign_smime_canonicalization(self):
        data = b"hello\nworld"
        cert, key = _load_cert_key()
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(data)
            .add_signer(cert, key, hashes.SHA256())
        )

        sig_binary = builder.sign(serialization.Encoding.DER, [])
        # LF gets converted to CR+LF (SMIME canonical form)
        # so data should not be present in the sig
        assert data not in sig_binary
        assert b"hello\r\nworld" in sig_binary
        # TODO: validate sig

    def test_smime_sign_text(self):
        data = b"hello world"
        cert, key = _load_cert_key()
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(data)
            .add_signer(cert, key, hashes.SHA256())
        )

        options = [
            smime.SMIMEOptions.Text,
            smime.SMIMEOptions.DetachedSignature,
        ]
        sig_pem = builder.sign(serialization.Encoding.PEM, options)
        sig_binary = builder.sign(serialization.Encoding.DER, options)
        # The text option adds text/plain headers to the S/MIME message
        # These headers are only relevant in PEM mode, not binary, which is
        # just the PKCS7 structure itself.
        assert b"text/plain" in sig_pem
        assert b"text/plain" not in sig_binary
        # TODO: validate sig

    def test_smime_sign_no_capabilities(self):
        data = b"hello world"
        cert, key = _load_cert_key()
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(data)
            .add_signer(cert, key, hashes.SHA256())
        )

        options = [smime.SMIMEOptions.NoCapabilities]
        sig_binary = builder.sign(serialization.Encoding.DER, options)
        # NoCapabilities removes the SMIMECapabilities attribute from the
        # PKCS7 structure. This is an ASN.1 sequence with the
        # OID 1.2.840.113549.1.9.15. It does NOT remove all authenticated
        # attributes, so we verify that by looking for the signingTime OID.

        # 1.2.840.113549.1.9.15 SMIMECapabilities as an ASN.1 DER encoded OID
        assert b"\x06\t*\x86H\x86\xf7\r\x01\t\x0f" not in sig_binary
        # 1.2.840.113549.1.9.5 signingTime as an ASN.1 DER encoded OID
        assert b"\x06\t*\x86H\x86\xf7\r\x01\t\x05" in sig_binary
        # TODO: validate sig

    def test_smime_sign_no_attributes(self):
        data = b"hello world"
        cert, key = _load_cert_key()
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(data)
            .add_signer(cert, key, hashes.SHA256())
        )

        options = [smime.SMIMEOptions.NoAttributes]
        sig_binary = builder.sign(serialization.Encoding.DER, options)
        # NoAttributes removes all authenticated attributes, so we shouldn't
        # find SMIMECapabilities or signingTime.

        # 1.2.840.113549.1.9.15 SMIMECapabilities as an ASN.1 DER encoded OID
        assert b"\x06\t*\x86H\x86\xf7\r\x01\t\x0f" not in sig_binary
        # 1.2.840.113549.1.9.5 signingTime as an ASN.1 DER encoded OID
        assert b"\x06\t*\x86H\x86\xf7\r\x01\t\x05" not in sig_binary
        # TODO: validate sig

    def test_multiple_signers(self):
        data = b"hello world"
        cert, key = _load_cert_key()
        rsa_key = load_vectors_from_file(
            os.path.join("x509", "custom", "ca", "rsa_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read(), None
            ),
            mode="rb",
        )
        rsa_cert = load_vectors_from_file(
            os.path.join("x509", "custom", "ca", "rsa_ca.pem"),
            loader=lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read()
            ),
            mode="rb",
        )
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(data)
            .add_signer(cert, key, hashes.SHA512())
            .add_signer(rsa_cert, rsa_key, hashes.SHA512())
        )
        sig = builder.sign(serialization.Encoding.DER, [])
        # There should be three SHA512 OIDs in this structure, so we search
        # for them all.
        results = re.findall(b"\\x06\\t`\\x86H\\x01e\\x03\\x04\\x02\\x03", sig)
        assert len(results) == 3

    def test_multiple_signers_different_hash_algs(self):
        data = b"hello world"
        cert, key = _load_cert_key()
        rsa_key = load_vectors_from_file(
            os.path.join("x509", "custom", "ca", "rsa_key.pem"),
            lambda pemfile: serialization.load_pem_private_key(
                pemfile.read(), None
            ),
            mode="rb",
        )
        rsa_cert = load_vectors_from_file(
            os.path.join("x509", "custom", "ca", "rsa_ca.pem"),
            loader=lambda pemfile: x509.load_pem_x509_certificate(
                pemfile.read()
            ),
            mode="rb",
        )
        builder = (
            smime.SMIMESignatureBuilder()
            .add_data(data)
            .add_signer(cert, key, hashes.SHA384())
            .add_signer(rsa_cert, rsa_key, hashes.SHA512())
        )
        sig = builder.sign(serialization.Encoding.DER, [])
        # There should be two SHA384 and two SHA512 OIDs in this structure, so
        # we search for them all.
        sha384 = re.findall(b"\\x06\\t`\\x86H\\x01e\\x03\\x04\\x02\\x02", sig)
        sha512 = re.findall(b"\\x06\\t`\\x86H\\x01e\\x03\\x04\\x02\\x03", sig)
        assert len(sha384) == 2
        assert len(sha512) == 2
