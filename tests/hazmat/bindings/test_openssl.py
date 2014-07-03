# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.hazmat.bindings.openssl.binding import (
    Binding, _get_windows_libraries
)


class TestOpenSSL(object):
    def test_binding_loads(self):
        binding = Binding()
        assert binding
        assert binding.lib
        assert binding.ffi

    def test_is_available(self):
        assert Binding.is_available() is True

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
        res = b.lib.Cryptography_add_osrandom_engine()
        assert res == 2

    def test_ssl_ctx_options(self):
        # Test that we're properly handling 32-bit unsigned on all platforms.
        b = Binding()
        assert b.lib.SSL_OP_ALL > 0
        ctx = b.lib.SSL_CTX_new(b.lib.TLSv1_method())
        ctx = b.ffi.gc(ctx, b.lib.SSL_CTX_free)
        resp = b.lib.SSL_CTX_set_options(ctx, b.lib.SSL_OP_ALL)
        assert resp == b.lib.SSL_OP_ALL
        assert b.lib.SSL_OP_ALL == b.lib.SSL_CTX_get_options(ctx)

    def test_ssl_options(self):
        # Test that we're properly handling 32-bit unsigned on all platforms.
        b = Binding()
        assert b.lib.SSL_OP_ALL > 0
        ctx = b.lib.SSL_CTX_new(b.lib.TLSv1_method())
        ctx = b.ffi.gc(ctx, b.lib.SSL_CTX_free)
        ssl = b.lib.SSL_new(ctx)
        ssl = b.ffi.gc(ssl, b.lib.SSL_free)
        resp = b.lib.SSL_set_options(ssl, b.lib.SSL_OP_ALL)
        assert resp == b.lib.SSL_OP_ALL
        assert b.lib.SSL_OP_ALL == b.lib.SSL_get_options(ssl)

    def test_ssl_mode(self):
        # Test that we're properly handling 32-bit unsigned on all platforms.
        b = Binding()
        assert b.lib.SSL_OP_ALL > 0
        ctx = b.lib.SSL_CTX_new(b.lib.TLSv1_method())
        ctx = b.ffi.gc(ctx, b.lib.SSL_CTX_free)
        ssl = b.lib.SSL_new(ctx)
        ssl = b.ffi.gc(ssl, b.lib.SSL_free)
        resp = b.lib.SSL_set_mode(ssl, b.lib.SSL_OP_ALL)
        assert resp == b.lib.SSL_OP_ALL
        assert b.lib.SSL_OP_ALL == b.lib.SSL_get_mode(ssl)

    def test_windows_static_dynamic_libraries(self):
        assert "ssleay32mt" in _get_windows_libraries("static")

        assert "ssleay32" in _get_windows_libraries("dynamic")

        with pytest.raises(ValueError):
            _get_windows_libraries("notvalid")
