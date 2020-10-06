# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.exceptions import InternalError
from cryptography.hazmat.bindings.openssl.binding import (
    Binding,
    _consume_errors,
    _openssl_assert,
    _verify_package_version,
)


def p_o_v_ffi(libversion, encoding="ascii"):
    """
    This is a convenience function for processing library identification
    metadata for use in version/variant-sensitive tests.

    Terse name due to PEP8 rules limiting code to 79 characters per line.
    Should be "process_openssl_version_ffi" or something similar

    Shamelessly copy+pasting in tests because I couldn't figure out a
    more 'elegant' method of applying this. This should probably be in
    the library's src folder somewhere but I don't want to disturb any
    boffins or eggheads exploring M-theory with my free hacks.

    Return value example: ['OpenSSL',['1','1','1g']]

    :param char* libversion: a cffi character array with metadata
    :param str encoding: the encoding used by the library for its metadata
    :return: tuple of form [Library_Name,[version,id,info,...]]
    :rtype: list
    :raises ValueError: if libversion doesn't evaluate into >=2 parts
    :raises ValueError: if libversion isn't a C string
    """
    libtext = Binding.ffi.string(libversion).decode(encoding).split(" ")
    if(len(libtext) < 2):
        err = "Library metadata lacked discernable name and version parts"
        raise ValueError(err)
    else:
        # Processing assumes OPENSSL_VERSION_TEXT format from OpenSSL 1.1.0
        libver = libtext[1].split(".")
        retval = list()
        retval.append(libtext[0])
        retval.append(libver)
        return retval


class TestLibraryVersion(object):
    """
    This is a necessary class to ensure that we're running the correct tests
    against our version/variant-sensitive test code (since we're accommodating
    3 releases of OpenSSL across 2 major versions and 4 releases of LibreSSL
    across 2 major versions (and that's before geopolitics get mixed in)

    This class validates functionality of library metadata processing
    mechanisms (so you know you're identifying the version correctly)
    """
    def test_p_o_v_ffi_works(self):
        libname = "OpenSSL"
        libversion = ["1", "0", "2u"]
        separator = "."
        versionstring = separator.join(libversion)
        testname = libname + " " + versionstring

        version = Binding.ffi.new("char[]", bytes(testname.encode("ascii")))
        retval = p_o_v_ffi(version)

        assert retval[0] == libname
        assert retval[1][0] == libversion[0]
        assert retval[1][1] == libversion[1]
        assert retval[1][2] == libversion[2]

    def test_p_o_v_ffi_exception(self):
        testname = "LibreSSL2.1.6"
        version = Binding.ffi.new("char[]", bytes(testname.encode("ascii")))
        with pytest.raises(ValueError):
            p_o_v_ffi(version)


class TestOpenSSL(object):

    _libname = p_o_v_ffi(Binding.lib.OPENSSL_VERSION_TEXT)[0]
    _libver = p_o_v_ffi(Binding.lib.OPENSSL_VERSION_TEXT)[1]

    def test_binding_loads(self):
        binding = Binding()
        assert binding
        assert binding.lib
        assert binding.ffi

    def test_crypto_lock_init(self):
        b = Binding()

        b.init_static_locks()
        lock_cb = b.lib.CRYPTO_get_locking_callback()
        if b.lib.CRYPTOGRAPHY_OPENSSL_110_OR_GREATER:
            assert lock_cb == b.ffi.NULL
            assert b.lib.Cryptography_HAS_LOCKING_CALLBACKS == 0
        else:
            assert lock_cb != b.ffi.NULL
            assert b.lib.Cryptography_HAS_LOCKING_CALLBACKS == 1

    def test_add_engine_more_than_once(self):
        b = Binding()
        b._register_osrandom_engine()
        assert b.lib.ERR_get_error() == 0

    def test_ssl_ctx_options(self):
        # Test that we're properly handling 32-bit unsigned on all platforms.
        b = Binding()
        assert b.lib.SSL_OP_ALL > 0
        ctx = b.lib.SSL_CTX_new(b.lib.SSLv23_method())
        assert ctx != b.ffi.NULL
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
        ctx = b.lib.SSL_CTX_new(b.lib.SSLv23_method())
        assert ctx != b.ffi.NULL
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
        ctx = b.lib.SSL_CTX_new(b.lib.SSLv23_method())
        assert ctx != b.ffi.NULL
        ctx = b.ffi.gc(ctx, b.lib.SSL_CTX_free)
        ssl = b.lib.SSL_new(ctx)
        ssl = b.ffi.gc(ssl, b.lib.SSL_free)
        current_options = b.lib.SSL_get_mode(ssl)
        resp = b.lib.SSL_set_mode(ssl, b.lib.SSL_OP_ALL)
        expected_options = current_options | b.lib.SSL_OP_ALL
        assert resp == expected_options
        assert b.lib.SSL_get_mode(ssl) == expected_options

    @pytest.mark.skipif(_libname == "OpenSSL" and
                        (int(_libver[0]) < 1 or
                         int(_libver[1]) < 1),
                        reason="TLS_method requires OpenSSL >= 1.1.0")
    def test_tls_ctx_options(self):
        # Test that we're properly handling 32-bit unsigned on all platforms.
        b = Binding()
        assert b.lib.SSL_OP_ALL > 0
        ctx = b.lib.SSL_CTX_new(b.lib.TLS_method())
        assert ctx != b.ffi.NULL
        ctx = b.ffi.gc(ctx, b.lib.SSL_CTX_free)
        current_options = b.lib.SSL_CTX_get_options(ctx)
        resp = b.lib.SSL_CTX_set_options(ctx, b.lib.SSL_OP_ALL)
        expected_options = current_options | b.lib.SSL_OP_ALL
        assert resp == expected_options
        assert b.lib.SSL_CTX_get_options(ctx) == expected_options

    @pytest.mark.skipif(_libname == "OpenSSL" and
                        (int(_libver[0]) < 1 or
                         int(_libver[1]) < 1),
                        reason="TLS_method requires OpenSSL >= 1.1.0")
    def test_tls_options(self):
        # Test that we're properly handling 32-bit unsigned on all platforms.
        b = Binding()
        assert b.lib.SSL_OP_ALL > 0
        ctx = b.lib.SSL_CTX_new(b.lib.TLS_method())
        assert ctx != b.ffi.NULL
        ctx = b.ffi.gc(ctx, b.lib.SSL_CTX_free)
        ssl = b.lib.SSL_new(ctx)
        ssl = b.ffi.gc(ssl, b.lib.SSL_free)
        current_options = b.lib.SSL_get_options(ssl)
        resp = b.lib.SSL_set_options(ssl, b.lib.SSL_OP_ALL)
        expected_options = current_options | b.lib.SSL_OP_ALL
        assert resp == expected_options
        assert b.lib.SSL_get_options(ssl) == expected_options

    @pytest.mark.skipif(_libname == "OpenSSL" and
                        (int(_libver[0]) < 1 or
                         int(_libver[1]) < 1),
                        reason="TLS_method requires OpenSSL >= 1.1.0")
    def test_tls_mode(self):
        # Test that we're properly handling 32-bit unsigned on all platforms.
        b = Binding()
        assert b.lib.SSL_OP_ALL > 0
        ctx = b.lib.SSL_CTX_new(b.lib.TLS_method())
        assert ctx != b.ffi.NULL
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

        if b.lib.CRYPTOGRAPHY_OPENSSL_110_OR_GREATER:
            assert b.lib.TLS_ST_OK
        else:
            with pytest.raises(AttributeError):
                b.lib.TLS_ST_OK

    def test_openssl_assert_error_on_stack(self):
        b = Binding()
        b.lib.ERR_put_error(
            b.lib.ERR_LIB_EVP,
            b.lib.EVP_F_EVP_ENCRYPTFINAL_EX,
            b.lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH,
            b"",
            -1,
        )
        with pytest.raises(InternalError) as exc_info:
            _openssl_assert(b.lib, False)

        error = exc_info.value.err_code[0]
        assert error.code == 101183626
        assert error.lib == b.lib.ERR_LIB_EVP
        assert error.func == b.lib.EVP_F_EVP_ENCRYPTFINAL_EX
        assert error.reason == b.lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH
        assert b"data not multiple of block length" in error.reason_text

    def test_check_startup_errors_are_allowed(self):
        b = Binding()
        b.lib.ERR_put_error(
            b.lib.ERR_LIB_EVP,
            b.lib.EVP_F_EVP_ENCRYPTFINAL_EX,
            b.lib.EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH,
            b"",
            -1,
        )
        b._register_osrandom_engine()
        assert _consume_errors(b.lib) == []

    def test_version_mismatch(self):
        with pytest.raises(ImportError):
            _verify_package_version("nottherightversion")
