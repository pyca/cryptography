# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.hazmat.bindings.openssl.binding import Binding


class TestOpenSSL(object):
    def test_binding_loads(self):
        binding = Binding()
        assert binding
        assert binding.lib
        assert binding.ffi

    def test_crypto_lock_init(self):
        b = Binding()
        b.init_static_locks()
        lock_cb = b.lib.CRYPTO_get_locking_callback()
        assert lock_cb != b.ffi.NULL

    def _skip_if_not_fallback_lock(self, b):
        # only run this test if we are using our locking cb
        original_cb = b.lib.CRYPTO_get_locking_callback()
        if original_cb != b._lock_cb_handle:
            pytest.skip(
                "Not using the fallback Python locking callback "
                "implementation. Probably because import _ssl set one"
            )

    def test_fallback_crypto_lock_via_openssl_api(self):
        b = Binding()
        b.init_static_locks()

        self._skip_if_not_fallback_lock(b)

        # check that the lock state changes appropriately
        lock = b._locks[b.lib.CRYPTO_LOCK_SSL]

        # starts out unlocked
        assert lock.acquire(False)
        lock.release()

        b.lib.CRYPTO_lock(
            b.lib.CRYPTO_LOCK | b.lib.CRYPTO_READ,
            b.lib.CRYPTO_LOCK_SSL, b.ffi.NULL, 0
        )

        # becomes locked
        assert not lock.acquire(False)

        b.lib.CRYPTO_lock(
            b.lib.CRYPTO_UNLOCK | b.lib.CRYPTO_READ,
            b.lib.CRYPTO_LOCK_SSL, b.ffi.NULL, 0
        )

        # then unlocked
        assert lock.acquire(False)
        lock.release()

    def test_fallback_crypto_lock_via_binding_api(self):
        b = Binding()
        b.init_static_locks()

        self._skip_if_not_fallback_lock(b)

        lock = b._locks[b.lib.CRYPTO_LOCK_SSL]

        with pytest.raises(RuntimeError):
            b._lock_cb(0, b.lib.CRYPTO_LOCK_SSL, "<test>", 1)

        # errors shouldn't cause locking
        assert lock.acquire(False)
        lock.release()

        b._lock_cb(b.lib.CRYPTO_LOCK | b.lib.CRYPTO_READ,
                   b.lib.CRYPTO_LOCK_SSL, "<test>", 1)
        # locked
        assert not lock.acquire(False)

        b._lock_cb(b.lib.CRYPTO_UNLOCK | b.lib.CRYPTO_READ,
                   b.lib.CRYPTO_LOCK_SSL, "<test>", 1)
        # unlocked
        assert lock.acquire(False)
        lock.release()

    def test_add_engine_more_than_once(self):
        b = Binding()
        with pytest.raises(RuntimeError):
            b._register_osrandom_engine()

    def test_ssl_ctx_options(self):
        # Test that we're properly handling 32-bit unsigned on all platforms.
        b = Binding()
        assert b.lib.SSL_OP_ALL > 0
        ctx = b.lib.SSL_CTX_new(b.lib.TLSv1_method())
        ctx = b.ffi.gc(ctx, b.lib.SSL_CTX_free)
        current_options = b.lib.SSL_CTX_get_options(ctx)
        resp = b.lib.SSL_CTX_set_options(ctx, b.lib.SSL_OP_ALL)
        expected_options = current_options | b.lib.SSL_OP_ALL
        assert resp == expected_options
        assert b.lib.SSL_CTX_get_options(ctx) == expected_options

    def test_ssl_options(self):
        # Test that we're properly handling 32-bit unsigned on all platforms.
        b = Binding()
        assert b.lib.SSL_OP_ALL > 0
        ctx = b.lib.SSL_CTX_new(b.lib.TLSv1_method())
        ctx = b.ffi.gc(ctx, b.lib.SSL_CTX_free)
        ssl = b.lib.SSL_new(ctx)
        ssl = b.ffi.gc(ssl, b.lib.SSL_free)
        current_options = b.lib.SSL_get_options(ssl)
        resp = b.lib.SSL_set_options(ssl, b.lib.SSL_OP_ALL)
        expected_options = current_options | b.lib.SSL_OP_ALL
        assert resp == expected_options
        assert b.lib.SSL_get_options(ssl) == expected_options

    def test_ssl_mode(self):
        # Test that we're properly handling 32-bit unsigned on all platforms.
        b = Binding()
        assert b.lib.SSL_OP_ALL > 0
        ctx = b.lib.SSL_CTX_new(b.lib.TLSv1_method())
        ctx = b.ffi.gc(ctx, b.lib.SSL_CTX_free)
        ssl = b.lib.SSL_new(ctx)
        ssl = b.ffi.gc(ssl, b.lib.SSL_free)
        current_options = b.lib.SSL_get_mode(ssl)
        resp = b.lib.SSL_set_mode(ssl, b.lib.SSL_OP_ALL)
        expected_options = current_options | b.lib.SSL_OP_ALL
        assert resp == expected_options
        assert b.lib.SSL_get_mode(ssl) == expected_options

    def test_conditional_removal(self):
        b = Binding()
        if b.lib.OPENSSL_VERSION_NUMBER >= 0x10000000:
            assert b.lib.X509_V_ERR_DIFFERENT_CRL_SCOPE
            assert b.lib.X509_V_ERR_CRL_PATH_VALIDATION_ERROR
        else:
            with pytest.raises(AttributeError):
                b.lib.X509_V_ERR_DIFFERENT_CRL_SCOPE

            with pytest.raises(AttributeError):
                b.lib.X509_V_ERR_CRL_PATH_VALIDATION_ERROR

        if b.lib.OPENSSL_VERSION_NUMBER >= 0x10001000:
            assert b.lib.CMAC_Init
        else:
            with pytest.raises(AttributeError):
                b.lib.CMAC_Init
