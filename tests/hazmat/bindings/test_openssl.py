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

import threading
import time

import pytest

from cryptography.hazmat.bindings.openssl.binding import Binding


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

    def test_our_crypto_lock(self, capfd):
        b = Binding()
        b.init_static_locks()

        # only run this test if we are using our locking cb
        original_cb = b.lib.CRYPTO_get_locking_callback()
        if original_cb != b._lock_cb_handle:
            pytest.skip("Not using Python locking callback implementation")

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

        # then test directly

        with pytest.raises(RuntimeError):
            b._lock_cb(0, b.lib.CRYPTO_LOCK_SSL, "<test>", 1)

        # errors shouldnt cause locking
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

    def test_crypto_lock_mutex(self):
        b = Binding()
        b.init_static_locks()

        # make sure whatever locking system we end up with actually acts
        # like a mutex.

        self._shared_value = 0

        def critical_loop():
            for i in range(10):
                b.lib.CRYPTO_lock(
                    b.lib.CRYPTO_LOCK | b.lib.CRYPTO_READ,
                    b.lib.CRYPTO_LOCK_SSL,
                    b.ffi.NULL,
                    0
                )

                assert self._shared_value == 0
                self._shared_value += 1
                time.sleep(0.01)
                assert self._shared_value == 1
                self._shared_value = 0

                b.lib.CRYPTO_lock(
                    b.lib.CRYPTO_UNLOCK | b.lib.CRYPTO_READ,
                    b.lib.CRYPTO_LOCK_SSL,
                    b.ffi.NULL,
                    0
                )

        threads = []
        for x in range(10):
            t = threading.Thread(target=critical_loop)
            t.start()
            threads.append(t)

        while threads:
            for t in threads:
                t.join(0.1)
                if not t.is_alive():
                    threads.remove(t)
