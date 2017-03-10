# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import json
import os
import subprocess
import sys
import textwrap

import pytest

from cryptography.hazmat.bindings.openssl.binding import Binding


MEMORY_LEAK_SCRIPT = """
def main():
    import ctypes.util
    import gc
    import json
    import sys

    import cffi

    from cryptography.hazmat.bindings._openssl import ffi, lib

    libc_ffi = cffi.FFI()
    libc_ffi.cdef('''
    void *malloc(size_t);
    void *realloc(void *, size_t);
    void free(void *);
    ''')
    raise ValueError(ctypes.util.find_library("c"))
    libc_lib = libc_ffi.dlopen(ctypes.util.find_library("c"))

    heap = {}

    @libc_ffi.callback("void *(size_t, const char *, int)")
    def malloc(size, path, line):
        ptr = libc_lib.malloc(size)
        heap[ptr] = (size, path, line)
        return ptr

    @libc_ffi.callback("void *(void *, size_t, const char *, int)")
    def realloc(ptr, size, path, line):
        del heap[ptr]
        new_ptr = libc_lib.realloc(ptr, size)
        heap[new_ptr] = (size, path, line)
        return new_ptr

    @libc_ffi.callback("void(void *, const char *, int)")
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

    # Swap back to the original functions so that if OpenSSL tries to free
    # something from its atexit handle it won't be going through a Python
    # function, which will be deallocated when this function returns
    result = lib.Cryptography_CRYPTO_set_mem_functions(
        ffi.addressof(lib, "Cryptography_malloc_wrapper"),
        ffi.addressof(lib, "Cryptography_realloc_wrapper"),
        ffi.addressof(lib, "Cryptography_free_wrapper"),
    )
    assert result == 1

    remaining = set(heap) - start_heap

    if remaining:
        sys.stdout.write(json.dumps(dict(
            (int(libc_ffi.cast("size_t", ptr)), {
                "size": heap[ptr][0],
                "path": libc_ffi.string(heap[ptr][1]).decode(),
                "line": heap[ptr][2]
            })
            for ptr in remaining
        )))
        sys.stdout.flush()
        sys.exit(255)

main()
"""


def assert_no_memory_leaks(s):
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(sys.path)
    proc = subprocess.Popen(
        [sys.executable, "-c", "{0}\n\n{1}".format(s, MEMORY_LEAK_SCRIPT)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    proc.wait()
    if proc.returncode == 255:
        out = json.loads(proc.stdout.read().decode())
        raise AssertionError(out)
    elif proc.returncode != 0:
        # Any exception type will do to be honest
        raise ValueError(proc.stdout.read(), proc.stderr.read())


def skip_if_memtesting_not_supported():
    return pytest.mark.skipif(
        not Binding().lib.Cryptography_HAS_MEM_FUNCTIONS,
        reason="Requires OpenSSL memory functions (>=1.1.0)"
    )


@skip_if_memtesting_not_supported()
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

    def test_errors(self):
        with pytest.raises(ValueError):
            assert_no_memory_leaks(textwrap.dedent("""
            def func():
                raise ZeroDivisionError
            """))
