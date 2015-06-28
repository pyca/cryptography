# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import threading

from cryptography.hazmat.bindings._openssl import ffi, lib

_osrandom_engine_id = ffi.new("const char[]", b"osrandom")
_osrandom_engine_name = ffi.new("const char[]", b"osrandom_engine")


@ffi.callback("int (*)(unsigned char *, int)", error=-1)
def _osrandom_rand_bytes(buf, size):
    signed = ffi.cast("char *", buf)
    result = os.urandom(size)
    signed[0:size] = result
    return 1


@ffi.callback("int (*)(void)")
def _osrandom_rand_status():
    return 1


_osrandom_method = ffi.new(
    "RAND_METHOD *",
    dict(bytes=_osrandom_rand_bytes, pseudorand=_osrandom_rand_bytes,
         status=_osrandom_rand_status)
)


def _register_osrandom_engine():
    assert lib.ERR_peek_error() == 0
    looked_up_engine = lib.ENGINE_by_id(_osrandom_engine_id)
    if looked_up_engine != ffi.NULL:
        raise RuntimeError("osrandom engine already registered")

    lib.ERR_clear_error()

    engine = lib.ENGINE_new()
    try:
        result = lib.ENGINE_set_id(engine, _osrandom_engine_id)
        assert result == 1
        result = lib.ENGINE_set_name(engine, _osrandom_engine_name)
        assert result == 1
        result = lib.ENGINE_set_RAND(engine, _osrandom_method)
        assert result == 1
        result = lib.ENGINE_add(engine)
        assert result == 1
    finally:
        result = lib.ENGINE_free(engine)
        assert result == 1


class Binding(object):
    """
    OpenSSL API wrapper.
    """
    lib = lib
    ffi = ffi
    _lib_loaded = False
    _locks = None
    _lock_cb_handle = None
    _rand_method = None
    _init_lock = threading.Lock()
    _lock_init_lock = threading.Lock()

    # aliases for the convenience of tests.
    _osrandom_engine_id = _osrandom_engine_id
    _osrandom_engine_name = _osrandom_engine_name
    _register_osrandom_engine = staticmethod(_register_osrandom_engine)

    def __init__(self):
        self._ensure_ffi_initialized()

    @classmethod
    def _ensure_ffi_initialized(cls):
        if cls._lib_loaded:
            return

        with cls._init_lock:
            if not cls._lib_loaded:
                cls._lib_loaded = True
                _register_osrandom_engine()

    @classmethod
    def init_static_locks(cls):
        with cls._lock_init_lock:
            cls._ensure_ffi_initialized()

            if not cls._lock_cb_handle:
                cls._lock_cb_handle = cls.ffi.callback(
                    "void(int, int, const char *, int)",
                    cls._lock_cb
                )

            # Use Python's implementation if available, importing _ssl triggers
            # the setup for this.
            __import__("_ssl")

            if cls.lib.CRYPTO_get_locking_callback() != cls.ffi.NULL:
                return

            # If nothing else has setup a locking callback already, we set up
            # our own
            num_locks = cls.lib.CRYPTO_num_locks()
            cls._locks = [threading.Lock() for n in range(num_locks)]

            cls.lib.CRYPTO_set_locking_callback(cls._lock_cb_handle)

    @classmethod
    def _lock_cb(cls, mode, n, file, line):
        lock = cls._locks[n]

        if mode & cls.lib.CRYPTO_LOCK:
            lock.acquire()
        elif mode & cls.lib.CRYPTO_UNLOCK:
            lock.release()
        else:
            raise RuntimeError(
                "Unknown lock mode {0}: lock={1}, file={2}, line={3}.".format(
                    mode, n, file, line
                )
            )
