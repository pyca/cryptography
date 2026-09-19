# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import hashlib
import os

import pytest

from cryptography import x509
from cryptography.exceptions import InternalError
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.bindings._rust import pyopenssl, test_support
from cryptography.hazmat.bindings.openssl.binding import (
    _openssl_assert,
    _verify_package_version,
)
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from tests.hazmat.primitives.test_rsa import rsa_key_2048

__all__ = ["rsa_key_2048"]


class TestOpenSSL:
    def test_binding_loads(self):
        context = pyopenssl.TLSContext(False)
        assert pyopenssl.TLSConnection(context, False)

    def test_ssl_ctx_options(self):
        options = pyopenssl.tls_constants()["SSL_OP_ALL"]
        if not (
            rust_openssl.CRYPTOGRAPHY_IS_BORINGSSL
            or rust_openssl.CRYPTOGRAPHY_IS_AWSLC
            or rust_openssl.CRYPTOGRAPHY_IS_LIBRESSL
        ):
            assert options > 0
        context = pyopenssl.TLSContext(False)
        current = context.set_options(0)
        assert context.set_options(options) == current | options
        assert context.set_options(0) == current | options

    def test_ssl_options(self):
        options = pyopenssl.tls_constants()["SSL_OP_ALL"]
        if not (
            rust_openssl.CRYPTOGRAPHY_IS_BORINGSSL
            or rust_openssl.CRYPTOGRAPHY_IS_AWSLC
            or rust_openssl.CRYPTOGRAPHY_IS_LIBRESSL
        ):
            assert options > 0
        connection = pyopenssl.TLSConnection(
            pyopenssl.TLSContext(False), False
        )
        current = connection.set_options(0)
        assert connection.set_options(options) == current | options
        assert connection.set_options(0) == current | options

    def test_conditional_removal(self):
        context = pyopenssl.TLSContext(False)
        capabilities = pyopenssl.tls_capabilities()
        if rust_openssl.CRYPTOGRAPHY_IS_LIBRESSL:
            assert "keylog" not in capabilities
            with pytest.raises(ValueError):
                context.enable_key_logging()
        else:
            assert "keylog" in capabilities
            context.enable_key_logging()

    def test_openssl_assert_error_on_stack(self):
        library, reason = test_support.queue_test_errors(1)
        with pytest.raises(InternalError) as exc_info:
            _openssl_assert(False)
        error = exc_info.value.err_code[0]
        assert error.lib == library
        assert error.reason == reason
        if not (
            rust_openssl.CRYPTOGRAPHY_IS_BORINGSSL
            or rust_openssl.CRYPTOGRAPHY_IS_AWSLC
        ):
            assert b"data not multiple of block length" in error.reason_text
        assert rust_openssl.capture_error_stack() == []

    def test_version_mismatch(self):
        with pytest.raises(ImportError):
            _verify_package_version("nottherightversion")

    def test_rust_internal_error(self):
        with pytest.raises(InternalError) as exc_info:
            rust_openssl.raise_openssl_error()
        assert len(exc_info.value.err_code) == 0
        library, reason = test_support.queue_test_errors(1)
        with pytest.raises(InternalError) as exc_info:
            rust_openssl.raise_openssl_error()
        error = exc_info.value.err_code[0]
        assert error.lib == library
        assert error.reason == reason
        if not (
            rust_openssl.CRYPTOGRAPHY_IS_BORINGSSL
            or rust_openssl.CRYPTOGRAPHY_IS_AWSLC
        ):
            assert b"data not multiple of block length" in error.reason_text
        assert rust_openssl.capture_error_stack() == []


class TestOwnedObjects:
    def test_names_copy_and_validate_attributes(self):
        name = pyopenssl.Name()
        assert name.get(b"CN") is None
        name.set(b"CN", b"original")
        name.set(b"C", b"US")
        copied = name.copy()
        assert copied.der() == name.der()
        assert copied.hash() == name.hash()
        assert copied.compare(name) == 0
        assert copied.compare(copied) == 0
        assert copied.components() == [(b"CN", b"original"), (b"C", b"US")]
        assert "original" in copied.display()
        copied.set(b"CN", b"changed")
        assert copied.get(b"CN") == "changed"
        assert name.get(b"CN") == "original"
        assert copied.compare(name) == -name.compare(copied) != 0
        assert pyopenssl.Name.from_der(name.der()).der() == name.der()
        for attribute in [b"CN\x00", b"not-an-attribute"]:
            with pytest.raises(ValueError):
                name.set(attribute, b"value")
        with pytest.raises((ValueError, pyopenssl.NativeError)):
            pyopenssl.Name.from_der(b"invalid")

    def test_certificate_roundtrip_and_store(self, rsa_key_2048, tmp_path):
        private_der = rsa_key_2048.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        public_der = rsa_key_2048.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        certificate = pyopenssl.Certificate()
        certificate.set_version(2)
        assert certificate.version() == 2
        certificate.set_serial(b"\x80\x01")
        assert certificate.serial() == (False, b"\x80\x01")
        name = pyopenssl.Name()
        name.set(b"CN", b"typed certificate")
        certificate.set_name(False, name)
        certificate.set_name(True, name)
        certificate.set_name_attribute(False, b"O", b"example")
        assert certificate.name(False).get(b"O") == "example"
        assert certificate.name(True).get(b"CN") == "typed certificate"
        certificate.set_name(False, name)
        certificate.set_public_key_der(public_der)
        assert certificate.public_key_der() == public_der
        assert certificate.time(False) is None
        certificate.adjust_time(False, -60)
        assert certificate.time(False) is not None
        certificate.set_time(False, b"20250101000000Z")
        certificate.set_time(True, b"20350101000000Z")
        assert certificate.time(True) == b"20350101000000Z"
        assert certificate.extension_count() == 0
        certificate.sign(private_der, "SHA256")
        der = certificate.encode(2)
        assert certificate.signature_algorithm() == b"sha256WithRSAEncryption"
        assert certificate.digest("SHA256") == hashlib.sha256(der).digest()
        pem = certificate.encode(1)
        assert b"BEGIN CERTIFICATE" in pem
        assert b"Certificate" in certificate.encode(65535)
        assert pyopenssl.Certificate.decode(pem, 1).encode(2) == der
        parsed = x509.load_der_x509_certificate(der)
        assert parsed.serial_number == 0x8001
        store = pyopenssl.TrustStore()
        store.set_time(1_800_000_000)
        with pytest.raises(pyopenssl.VerificationError):
            store.verify(der, [])
        store.add_certificate_der(der)
        store.set_flags(0)
        assert store.verify(der, []) == [der]
        certificate.set_serial(b"\x02")
        assert store.verify(der, []) == [der]
        with pytest.raises((pyopenssl.NativeError, ValueError)):
            store.verify(b"invalid", [])
        path = tmp_path / "ca.pem"
        path.write_bytes(pem)
        loaded = pyopenssl.TrustStore()
        loaded.load_locations(file=os.fsencode(path))
        loaded.set_time(1_800_000_000)
        assert loaded.verify(der, []) == [der]
        loaded.load_locations(directory=os.fsencode(tmp_path))
        for encoding in [0, 65535]:
            with pytest.raises(ValueError):
                pyopenssl.Certificate.decode(der, encoding)
        with pytest.raises(ValueError):
            certificate.encode(0)
        certificate.set_version(-1)
        assert certificate.version() == -1
        with pytest.raises(ValueError):
            certificate.set_time(False, b"invalid")
        with pytest.raises(ValueError):
            certificate.set_time(False, b"20250101000000Z\x00")

    def test_private_key_exports_and_runtime(self, rsa_key_2048):
        der = rsa_key_2048.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        plain = pyopenssl.private_key_pem(der, None, None)
        loaded_plain = serialization.load_pem_private_key(plain, None)
        assert isinstance(loaded_plain, rsa.RSAPrivateKey)
        assert loaded_plain.private_numbers() == rsa_key_2048.private_numbers()
        encrypted = pyopenssl.private_key_pem(
            der, b"aes-256-cbc", b"pass\x00word"
        )
        loaded_encrypted = serialization.load_pem_private_key(
            encrypted, b"pass\x00word"
        )
        assert isinstance(loaded_encrypted, rsa.RSAPrivateKey)
        assert (
            loaded_encrypted.private_numbers()
            == rsa_key_2048.private_numbers()
        )
        assert b"privateExponent" in pyopenssl.rsa_private_key_text(der)
        for cipher, password in [
            (b"unknown", b"password"),
            (b"aes-256-cbc", None),
            (None, b"password"),
            (b"aes\x00", b"password"),
        ]:
            with pytest.raises(ValueError):
                pyopenssl.private_key_pem(der, cipher, password)
        assert "prime256v1" in pyopenssl.curve_names()
        assert pyopenssl.compiled_version_text()
        pyopenssl.random_mix(b"untrusted supplemental input")
        assert pyopenssl.random_ready()
        with pytest.raises(ValueError):
            pyopenssl.legacy_dsa_private_key_der(511)
