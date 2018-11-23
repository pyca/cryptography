# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.hazmat.primitives.asymmetric.x448 import (
    X448PrivateKey, X448PublicKey
)

_X448_KEY_SIZE = 56


@utils.register_interface(X448PublicKey)
class _X448PublicKey(object):

    def __init__(self, backend, evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey

    def public_bytes(self):
        buf = self._backend._ffi.new("unsigned char []", _X448_KEY_SIZE)
        buflen = self._backend._ffi.new("size_t *", _X448_KEY_SIZE)
        res = self._backend._lib.EVP_PKEY_get_raw_public_key(
            self._evp_pkey, buf, buflen
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(buflen[0] == _X448_KEY_SIZE)
        return self._backend._ffi.buffer(buf, _X448_KEY_SIZE)[:]


@utils.register_interface(X448PrivateKey)
class _X448PrivateKey(object):
    def __init__(self, backend, evp_pkey):
        self._backend = backend
        self._evp_pkey = evp_pkey

    def public_key(self):
        buf = self._backend._ffi.new("unsigned char []", _X448_KEY_SIZE)
        buflen = self._backend._ffi.new("size_t *", _X448_KEY_SIZE)
        res = self._backend._lib.EVP_PKEY_get_raw_public_key(
            self._evp_pkey, buf, buflen
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(buflen[0] == _X448_KEY_SIZE)
        return self._backend.x448_load_public_bytes(buf)

    def exchange(self, peer_public_key):
        if not isinstance(peer_public_key, X448PublicKey):
            raise TypeError("peer_public_key must be X448PublicKey.")

        ctx = self._backend._lib.EVP_PKEY_CTX_new(
            self._evp_pkey, self._backend._ffi.NULL
        )
        self._backend.openssl_assert(ctx != self._backend._ffi.NULL)
        ctx = self._backend._ffi.gc(ctx, self._backend._lib.EVP_PKEY_CTX_free)
        res = self._backend._lib.EVP_PKEY_derive_init(ctx)
        self._backend.openssl_assert(res == 1)
        res = self._backend._lib.EVP_PKEY_derive_set_peer(
            ctx, peer_public_key._evp_pkey
        )
        self._backend.openssl_assert(res == 1)
        keylen = self._backend._ffi.new("size_t *")
        res = self._backend._lib.EVP_PKEY_derive(
            ctx, self._backend._ffi.NULL, keylen
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(keylen[0] > 0)
        buf = self._backend._ffi.new("unsigned char[]", keylen[0])
        res = self._backend._lib.EVP_PKEY_derive(ctx, buf, keylen)
        self._backend.openssl_assert(res == 1)
        return self._backend._ffi.buffer(buf, keylen[0])[:]
