# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import subprocess
import sys
import textwrap

import pytest


MEMORY_LEAK_SCRIPT = """
def main():
    import gc
    import sys

    import cffi

    from cryptography.hazmat.bindings._openssl import ffi, lib

    libc_ffi = cffi.FFI()
    libc_ffi.cdef('''
    void *malloc(size_t);
    void *realloc(void *, size_t);
    void free(void *);
    ''')
    libc_lib = libc_ffi.dlopen("libc")

    heap = {}

    @ffi.callback("void *(size_t, const char *, int)")
    def malloc(size, path, line):
        ptr = libc_lib.malloc(size)
        heap[ptr] = (size, libc_ffi.string(path), line)
        return ptr

    @ffi.callback("void *(void *, size_t, const char *, int)")
    def realloc(ptr, size, path, line):
        # TODO: this may need to be `heap.pop(ptr)`
        del heap[ptr]
        new_ptr = libc_lib.realloc(ptr, size)
        heap[new_ptr] = (size, path, line)
        return new_ptr

    @ffi.callback("void(void *, const char *, int)")
    def free(ptr, path, line):
        if ptr != libc_ffi.NULL:
            del heap[ptr]
            libc_lib.free(ptr)

    result = lib.Cryptography_CRYPTO_set_mem_functions(malloc, realloc, free)
    assert result == 1

    # Trigger a bunch of initialization stuff.
    from cryptography.hazmat.bindings.openssl.binding import Binding
    Binding()

    start_heap = set(heap)
    func()
    gc.collect()
    gc.collect()
    gc.collect()
    after_heap = set(heap)

    if after_heap - start_heap:
        sys.stderr.write(repr(heap))
        sys.exit(1)

main()
"""


def assert_no_memory_leaks(s):
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(sys.path)
    subprocess.check_call(
        [sys.executable, "-c", "{}\n\n{}".format(s, MEMORY_LEAK_SCRIPT)],
        env=env,
    )


class TestAssertNoMemoryLeaks(object):
    def test_no_leak_no_malloc(self):
        assert_no_memory_leaks(textwrap.dedent("""
        def func():
            pass
        """))

    def test_no_leak_free(self):
        assert_no_memory_leaks(textwrap.dedent("""
        def func():
            from cryptography.hazmat.bindings.openssl.binding import Binding
            b = Binding()
            name = b.lib.X509_NAME_new()
            b.lib.X509_NAME_free(name)
        """))

    def test_no_leak_gc(self):
        assert_no_memory_leaks(textwrap.dedent("""
        def func():
            from cryptography.hazmat.bindings.openssl.binding import Binding
            b = Binding()
            name = b.lib.X509_NAME_new()
            b.ffi.gc(name, b.lib.X509_NAME_free)
        """))

    def test_leak(self):
        with pytest.raises(AssertionError):
            assert_no_memory_leaks(textwrap.dedent("""
            def func():
                from cryptography.hazmat.bindings.openssl.binding import (
                    Binding
                )
                b = Binding()
                b.lib.X509_NAME_new()
            """))
