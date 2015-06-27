# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os
import threading

from cryptography.hazmat.bindings._openssl import ffi, lib


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
    _osrandom_engine_id = ffi.new("const char[]", b"osrandom")
    _osrandom_engine_name = ffi.new("const char[]", b"osrandom_engine")
    _retained = []

    def __init__(self):
        self._ensure_ffi_initialized()

    @classmethod
    def _ensure_ffi_initialized(cls):
        if cls._lib_loaded:
            return

        with cls._init_lock:
            if not cls._lib_loaded:
                cls._lib_loaded = True
                res = cls._register_osrandom_engine()
                assert res != 0

    @classmethod
    def _register_osrandom_engine(cls):
        if cls._retained:
            return 2

        def retain(it):
            cls._retained.append(it)
            return it
        method = cls.ffi.new("RAND_METHOD*")
        retain(method)
        method.seed = cls.ffi.NULL

        @retain
        @cls.ffi.callback("int (*)(unsigned char *, int)", error=0)
        def osrandom_rand_bytes(buf, size):
            signed = cls.ffi.cast("char*", buf)
            result = os.urandom(size)
            signed[0:size] = result
            return 1

        @retain
        @cls.ffi.callback("int (*)(unsigned char *, int)", error=0)
        def osrandom_pseudo_rand_bytes(buf, size):
            result = osrandom_rand_bytes(buf, size)
            if result == 0:
                return -1
            else:
                return result

        @retain
        @cls.ffi.callback("int (*)(void)", error=0)
        def osrandom_rand_status():
            return 1

        @retain
        @cls.ffi.callback("ENGINE_GEN_INT_FUNC_PTR", error=0)
        def osrandom_init(engine):
            return 1

        @retain
        @cls.ffi.callback("ENGINE_GEN_INT_FUNC_PTR", error=0)
        def osrandom_finish(engine):
            return 1

        method.bytes = osrandom_rand_bytes
        method.cleanup = cls.ffi.NULL
        method.add = cls.ffi.NULL
        method.pseudorand = osrandom_pseudo_rand_bytes
        method.status = osrandom_rand_status

        e = cls.lib.ENGINE_new()
        result = (cls.lib.ENGINE_set_id(e, cls._osrandom_engine_id)
                  and cls.lib.ENGINE_set_name(e, cls._osrandom_engine_name)
                  and cls.lib.ENGINE_set_RAND(e, method)
                  and cls.lib.ENGINE_set_init_function(e, osrandom_init)
                  and cls.lib.ENGINE_set_finish_function(e, osrandom_finish)
                  and cls.lib.ENGINE_add(e))
        if not cls.lib.ENGINE_free(e):
            return 0
        assert cls.lib.ENGINE_by_id(cls._osrandom_engine_id) != cls.ffi.NULL
        return result

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
