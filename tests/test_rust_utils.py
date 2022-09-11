# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import gc
import threading

from cryptography.hazmat.bindings._rust import FixedPool


class TestFixedPool:
    def test_basic(self):
        c = 0
        events = []

        def create():
            nonlocal c
            c += 1
            events.append(("create", c))
            return c

        pool = FixedPool(create)
        assert events == [("create", 1)]
        with pool.acquire() as c:
            assert c == 1
            assert events == [("create", 1)]

            with pool.acquire() as c:
                assert c == 2
                assert events == [("create", 1), ("create", 2)]

            assert events == [("create", 1), ("create", 2)]

        assert events == [("create", 1), ("create", 2)]

        del pool
        gc.collect()
        gc.collect()
        gc.collect()

        assert events == [
            ("create", 1),
            ("create", 2),
        ]

    def test_thread_stress(self):
        def create():
            return None

        pool = FixedPool(create)

        def thread_fn():
            with pool.acquire():
                pass

        threads = []
        for i in range(1024):
            t = threading.Thread(target=thread_fn)
            t.start()
            threads.append(t)

        for t in threads:
            t.join()
