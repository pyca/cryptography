# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import pytest

from cryptography.exceptions import InternalError
from cryptography.hazmat.bindings._rust import openssl as rust_openssl
from cryptography.hazmat.bindings._rust import pyopenssl, test_support
from cryptography.hazmat.bindings.openssl.binding import (
    _openssl_assert,
    _verify_package_version,
)


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
