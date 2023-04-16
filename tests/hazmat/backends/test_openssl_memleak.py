# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import json
import os
import platform
import subprocess
import sys
import textwrap

import pytest

from cryptography.hazmat.bindings.openssl.binding import Binding

MEMORY_LEAK_SCRIPT = """
import sys


def main(argv):
    import gc
    import json

    import cffi

    from cryptography.hazmat.bindings._rust import _openssl

    heap = {}
    start_heap = {}
    start_heap_realloc_delta = [0]  # 1-item list so callbacks can mutate it

    BACKTRACE_ENABLED = False
    if BACKTRACE_ENABLED:
        backtrace_ffi = cffi.FFI()
        backtrace_ffi.cdef('''
            int backtrace(void **, int);
            char **backtrace_symbols(void *const *, int);
        ''')
        backtrace_lib = backtrace_ffi.dlopen(None)

        def backtrace():
            buf = backtrace_ffi.new("void*[]", 24)
            length = backtrace_lib.backtrace(buf, len(buf))
            return (buf, length)

        def symbolize_backtrace(trace):
            (buf, length) = trace
            symbols = backtrace_lib.backtrace_symbols(buf, length)
            stack = [
                backtrace_ffi.string(symbols[i]).decode()
                for i in range(length)
            ]
            _openssl.lib.Cryptography_free_wrapper(
                symbols, backtrace_ffi.NULL, 0
            )
            return stack
    else:
        def backtrace():
            return None

        def symbolize_backtrace(trace):
            return None

    @_openssl.ffi.callback("void *(size_t, const char *, int)")
    def malloc(size, path, line):
        ptr = _openssl.lib.Cryptography_malloc_wrapper(size, path, line)
        heap[ptr] = (size, path, line, backtrace())
        return ptr

    @_openssl.ffi.callback("void *(void *, size_t, const char *, int)")
    def realloc(ptr, size, path, line):
        if ptr != _openssl.ffi.NULL:
            del heap[ptr]
        new_ptr = _openssl.lib.Cryptography_realloc_wrapper(
            ptr, size, path, line
        )
        heap[new_ptr] = (size, path, line, backtrace())

        # It is possible that something during the test will cause a
        # realloc of memory allocated during the startup phase. (This
        # was observed in conda-forge Windows builds of this package with
        # provider operation_bits pointers in crypto/provider_core.c.) If
        # we don't pay attention to that, the realloc'ed pointer will show
        # up as a leak; but we also don't want to allow this kind of realloc
        # to consume large amounts of additional memory. So we track the
        # realloc and the change in memory consumption.
        startup_info = start_heap.pop(ptr, None)
        if startup_info is not None:
            start_heap[new_ptr] = heap[new_ptr]
            start_heap_realloc_delta[0] += size - startup_info[0]

        return new_ptr

    @_openssl.ffi.callback("void(void *, const char *, int)")
    def free(ptr, path, line):
        if ptr != _openssl.ffi.NULL:
            del heap[ptr]
            _openssl.lib.Cryptography_free_wrapper(ptr, path, line)

    result = _openssl.lib.Cryptography_CRYPTO_set_mem_functions(
        malloc, realloc, free
    )
    assert result == 1

    # Trigger a bunch of initialization stuff.
    import hashlib
    from cryptography.hazmat.backends.openssl.backend import backend

    hashlib.sha256()

    start_heap.update(heap)

    try:
        func(*argv[1:])
    finally:
        gc.collect()
        gc.collect()
        gc.collect()

        if _openssl.lib.CRYPTOGRAPHY_OPENSSL_300_OR_GREATER:
            _openssl.lib.OSSL_PROVIDER_unload(backend._binding._legacy_provider)
            _openssl.lib.OSSL_PROVIDER_unload(backend._binding._default_provider)

        _openssl.lib.OPENSSL_cleanup()

        # Swap back to the original functions so that if OpenSSL tries to free
        # something from its atexit handle it won't be going through a Python
        # function, which will be deallocated when this function returns
        result = _openssl.lib.Cryptography_CRYPTO_set_mem_functions(
            _openssl.ffi.addressof(
                _openssl.lib, "Cryptography_malloc_wrapper"
            ),
            _openssl.ffi.addressof(
                _openssl.lib, "Cryptography_realloc_wrapper"
            ),
            _openssl.ffi.addressof(_openssl.lib, "Cryptography_free_wrapper"),
        )
        assert result == 1

    remaining = set(heap) - set(start_heap)

    # The constant here is the number of additional bytes of memory
    # consumption that are allowed in reallocs of start_heap memory.
    if remaining or start_heap_realloc_delta[0] > 3072:
        info = dict(
            (int(_openssl.ffi.cast("size_t", ptr)), {
                "size": heap[ptr][0],
                "path": _openssl.ffi.string(heap[ptr][1]).decode(),
                "line": heap[ptr][2],
                "backtrace": symbolize_backtrace(heap[ptr][3]),
            })
            for ptr in remaining
        )
        info["start_heap_realloc_delta"] = start_heap_realloc_delta[0]
        sys.stdout.write(json.dumps(info))
        sys.stdout.flush()
        sys.exit(255)

main(sys.argv)
"""


def assert_no_memory_leaks(s, argv=[]):
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(sys.path)

    # When using pytest-cov it attempts to instrument subprocesses. This
    # causes the memleak tests to raise exceptions.
    # we don't need coverage so we remove the env vars.
    env.pop("COV_CORE_CONFIG", None)
    env.pop("COV_CORE_DATAFILE", None)
    env.pop("COV_CORE_SOURCE", None)

    argv = [
        sys.executable,
        "-c",
        f"{s}\n\n{MEMORY_LEAK_SCRIPT}",
    ] + argv
    # Shell out to a fresh Python process because OpenSSL does not allow you to
    # install new memory hooks after the first malloc/free occurs.
    proc = subprocess.Popen(
        argv,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert proc.stdout is not None
    assert proc.stderr is not None
    try:
        proc.wait()
        if proc.returncode == 255:
            # 255 means there was a leak, load the info about what mallocs
            # weren't freed.
            out = json.loads(proc.stdout.read().decode())
            raise AssertionError(out)
        elif proc.returncode != 0:
            # Any exception type will do to be honest
            raise ValueError(proc.stdout.read(), proc.stderr.read())
    finally:
        proc.stdout.close()
        proc.stderr.close()


def skip_if_memtesting_not_supported():
    return pytest.mark.skipif(
        not Binding().lib.Cryptography_HAS_MEM_FUNCTIONS
        or platform.python_implementation() == "PyPy",
        reason="Requires OpenSSL memory functions (>=1.1.0) and not PyPy",
    )


@pytest.mark.skip_fips(reason="FIPS self-test sets allow_customize = 0")
@skip_if_memtesting_not_supported()
class TestAssertNoMemoryLeaks:
    def test_no_leak_no_malloc(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            pass
        """
            )
        )

    def test_no_leak_free(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            from cryptography.hazmat.bindings.openssl.binding import Binding
            b = Binding()
            name = b.lib.X509_NAME_new()
            b.lib.X509_NAME_free(name)
        """
            )
        )

    def test_no_leak_gc(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            from cryptography.hazmat.bindings.openssl.binding import Binding
            b = Binding()
            name = b.lib.X509_NAME_new()
            b.ffi.gc(name, b.lib.X509_NAME_free)
        """
            )
        )

    def test_leak(self):
        with pytest.raises(AssertionError):
            assert_no_memory_leaks(
                textwrap.dedent(
                    """
            def func():
                from cryptography.hazmat.bindings.openssl.binding import (
                    Binding
                )
                b = Binding()
                b.lib.X509_NAME_new()
            """
                )
            )

    def test_errors(self):
        with pytest.raises(ValueError, match="ZeroDivisionError"):
            assert_no_memory_leaks(
                textwrap.dedent(
                    """
            def func():
                raise ZeroDivisionError
            """
                )
            )


@pytest.mark.skip_fips(reason="FIPS self-test sets allow_customize = 0")
@skip_if_memtesting_not_supported()
class TestOpenSSLMemoryLeaks:
    def test_ec_private_numbers_private_key(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            from cryptography.hazmat.backends.openssl import backend
            from cryptography.hazmat.primitives.asymmetric import ec

            ec.EllipticCurvePrivateNumbers(
                private_value=int(
                    '280814107134858470598753916394807521398239633534281633982576099083'
                    '35787109896602102090002196616273211495718603965098'
                ),
                public_numbers=ec.EllipticCurvePublicNumbers(
                    curve=ec.SECP384R1(),
                    x=int(
                        '10036914308591746758780165503819213553101287571902957054148542'
                        '504671046744460374996612408381962208627004841444205030'
                    ),
                    y=int(
                        '17337335659928075994560513699823544906448896792102247714689323'
                        '575406618073069185107088229463828921069465902299522926'
                    )
                )
            ).private_key(backend)
        """
            )
        )

    def test_ec_derive_private_key(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            from cryptography.hazmat.backends.openssl import backend
            from cryptography.hazmat.primitives.asymmetric import ec
            ec.derive_private_key(1, ec.SECP256R1(), backend)
        """
            )
        )

    def test_x25519_pubkey_from_private_key(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            from cryptography.hazmat.primitives.asymmetric import x25519
            private_key = x25519.X25519PrivateKey.generate()
            private_key.public_key()
        """
            )
        )

    @pytest.mark.parametrize(
        "path",
        ["pkcs12/cert-aes256cbc-no-key.p12", "pkcs12/cert-key-aes256cbc.p12"],
    )
    def test_load_pkcs12_key_and_certificates(self, path):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func(path):
            from cryptography import x509
            from cryptography.hazmat.backends.openssl import backend
            from cryptography.hazmat.primitives.serialization import pkcs12
            import cryptography_vectors

            with cryptography_vectors.open_vector_file(path, "rb") as f:
                pkcs12.load_key_and_certificates(
                    f.read(), b"cryptography", backend
                )
        """
            ),
            [path],
        )

    def test_write_pkcs12_key_and_certificates(self):
        assert_no_memory_leaks(
            textwrap.dedent(
                """
        def func():
            import os
            from cryptography import x509
            from cryptography.hazmat.backends.openssl import backend
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.serialization import pkcs12
            import cryptography_vectors

            path = os.path.join('x509', 'custom', 'ca', 'ca.pem')
            with cryptography_vectors.open_vector_file(path, "rb") as f:
                cert = x509.load_pem_x509_certificate(
                    f.read(), backend
                )
            path2 = os.path.join('x509', 'custom', 'dsa_selfsigned_ca.pem')
            with cryptography_vectors.open_vector_file(path2, "rb") as f:
                cert2 = x509.load_pem_x509_certificate(
                    f.read(), backend
                )
            path3 = os.path.join('x509', 'letsencryptx3.pem')
            with cryptography_vectors.open_vector_file(path3, "rb") as f:
                cert3 = x509.load_pem_x509_certificate(
                    f.read(), backend
                )
            key_path = os.path.join("x509", "custom", "ca", "ca_key.pem")
            with cryptography_vectors.open_vector_file(key_path, "rb") as f:
                key = serialization.load_pem_private_key(
                    f.read(), None, backend
                )
            encryption = serialization.NoEncryption()
            pkcs12.serialize_key_and_certificates(
                b"name", key, cert, [cert2, cert3], encryption)
        """
            )
        )
