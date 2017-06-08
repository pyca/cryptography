# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography.exceptions import InvalidTag


_ENCRYPT = 1
_DECRYPT = 0


def _chacha20poly1305_setup(backend, key, nonce, tag, operation):
    evp_cipher = backend._lib.EVP_get_cipherbyname(b"chacha20-poly1305")
    ctx = backend._lib.EVP_CIPHER_CTX_new()
    ctx = backend._ffi.gc(ctx, backend._lib.EVP_CIPHER_CTX_free)
    res = backend._lib.EVP_CipherInit_ex(
        ctx, evp_cipher,
        backend._ffi.NULL,
        backend._ffi.NULL,
        backend._ffi.NULL,
        int(operation == _ENCRYPT)
    )
    backend.openssl_assert(res != 0)
    res = backend._lib.EVP_CIPHER_CTX_set_key_length(ctx, len(key))
    backend.openssl_assert(res != 0)
    res = backend._lib.EVP_CIPHER_CTX_ctrl(
        ctx, backend._lib.EVP_CTRL_AEAD_SET_IVLEN, len(nonce),
        backend._ffi.NULL
    )
    backend.openssl_assert(res != 0)
    if operation == _DECRYPT:
        res = backend._lib.EVP_CIPHER_CTX_ctrl(
            ctx, backend._lib.EVP_CTRL_AEAD_SET_TAG, len(tag), tag
        )
        backend.openssl_assert(res != 0)

    res = backend._lib.EVP_CipherInit_ex(
        ctx,
        backend._ffi.NULL,
        backend._ffi.NULL,
        key,
        nonce,
        int(operation == _ENCRYPT)
    )
    backend.openssl_assert(res != 0)
    return ctx


def _process_aad(backend, ctx, associated_data):
    outlen = backend._ffi.new("int *")
    res = backend._lib.EVP_CipherUpdate(
        ctx, backend._ffi.NULL, outlen, associated_data, len(associated_data)
    )
    backend.openssl_assert(res != 0)


def _process_data(backend, ctx, data):
    outlen = backend._ffi.new("int *")
    buf = backend._ffi.new("unsigned char[]", len(data))
    res = backend._lib.EVP_CipherUpdate(ctx, buf, outlen, data, len(data))
    backend.openssl_assert(res != 0)
    return backend._ffi.buffer(buf, outlen[0])[:]


def encrypt(backend, key, nonce, data, associated_data):
    ctx = _chacha20poly1305_setup(backend, key, nonce, None, _ENCRYPT)

    _process_aad(backend, ctx, associated_data)
    processed_data = _process_data(backend, ctx, data)
    outlen = backend._ffi.new("int *")
    res = backend._lib.EVP_CipherFinal_ex(ctx, backend._ffi.NULL, outlen)
    backend.openssl_assert(res != 0)
    backend.openssl_assert(outlen[0] == 0)
    # get the tag
    tag_buf = backend._ffi.new("unsigned char[]", 16)
    res = backend._lib.EVP_CIPHER_CTX_ctrl(
        ctx, backend._lib.EVP_CTRL_AEAD_GET_TAG, 16, tag_buf
    )
    backend.openssl_assert(res != 0)
    tag = backend._ffi.buffer(tag_buf)[:]

    return processed_data + tag


def decrypt(backend, key, nonce, data, associated_data):
    if len(data) < 16:
        raise InvalidTag
    tag = data[-16:]
    data = data[:-16]
    ctx = _chacha20poly1305_setup(backend, key, nonce, tag, _DECRYPT)
    _process_aad(backend, ctx, associated_data)
    processed_data = _process_data(backend, ctx, data)
    outlen = backend._ffi.new("int *")
    res = backend._lib.EVP_CipherFinal_ex(ctx, backend._ffi.NULL, outlen)
    if res == 0:
        backend._consume_errors()
        raise InvalidTag

    return processed_data
