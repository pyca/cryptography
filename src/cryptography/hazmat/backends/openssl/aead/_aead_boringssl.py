# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import typing

from cryptography.exceptions import InvalidTag

if typing.TYPE_CHECKING:
    from cryptography.hazmat.backends.openssl.aead import _AEADTypes
    from cryptography.hazmat.backends.openssl.backend import Backend


def _get_cipher(backend: Backend, cipher: _AEADTypes):
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    # Currently only ChaCha20-Poly1305 is supported using this API
    assert isinstance(cipher, ChaCha20Poly1305)
    return backend._lib.EVP_aead_chacha20_poly1305()


def _aead_create_ctx(
    backend: Backend,
    cipher: _AEADTypes,
    key: bytes,
    tag_len: typing.Optional[int] = None,
):
    aead_cipher = _get_cipher(backend, cipher)
    assert aead_cipher is not None
    key_ptr = backend._ffi.from_buffer(key)
    tag_len = (
        backend._lib.EVP_AEAD_DEFAULT_TAG_LENGTH
        if tag_len is None
        else tag_len
    )
    ctx = backend._lib.Cryptography_EVP_AEAD_CTX_new(
        aead_cipher, key_ptr, len(key), tag_len
    )
    backend.openssl_assert(ctx != backend._ffi.NULL)
    ctx = backend._ffi.gc(ctx, backend._lib.EVP_AEAD_CTX_free)
    return ctx


def _encrypt(
    backend: Backend,
    cipher: _AEADTypes,
    nonce: bytes,
    data: bytes,
    associated_data: typing.List[bytes],
    tag_length: int,
    ctx: typing.Any,
) -> bytes:
    assert ctx is not None

    aead_cipher = _get_cipher(backend, cipher)
    assert aead_cipher is not None

    out_len = backend._ffi.new("size_t *")
    #  max_out_len should be in_len plus the result of EVP_AEAD_max_overhead.
    max_out_len = len(data) + backend._lib.EVP_AEAD_max_overhead(aead_cipher)
    out_buf = backend._ffi.new("uint8_t[]", max_out_len)
    data_ptr = backend._ffi.from_buffer(data)
    nonce_ptr = backend._ffi.from_buffer(nonce)
    aad = b"".join(associated_data)
    aad_ptr = backend._ffi.from_buffer(aad)

    res = backend._lib.EVP_AEAD_CTX_seal(
        ctx,
        out_buf,
        out_len,
        max_out_len,
        nonce_ptr,
        len(nonce),
        data_ptr,
        len(data),
        aad_ptr,
        len(aad),
    )
    backend.openssl_assert(res == 1)
    encrypted_data = backend._ffi.buffer(out_buf, out_len[0])[:]
    return encrypted_data


def _decrypt(
    backend: Backend,
    cipher: _AEADTypes,
    nonce: bytes,
    data: bytes,
    associated_data: typing.List[bytes],
    tag_length: int,
    ctx: typing.Any,
) -> bytes:
    if len(data) < tag_length:
        raise InvalidTag

    assert ctx is not None

    out_len = backend._ffi.new("size_t *")
    #  max_out_len should at least in_len
    max_out_len = len(data)
    out_buf = backend._ffi.new("uint8_t[]", max_out_len)
    data_ptr = backend._ffi.from_buffer(data)
    nonce_ptr = backend._ffi.from_buffer(nonce)
    aad = b"".join(associated_data)
    aad_ptr = backend._ffi.from_buffer(aad)

    res = backend._lib.EVP_AEAD_CTX_open(
        ctx,
        out_buf,
        out_len,
        max_out_len,
        nonce_ptr,
        len(nonce),
        data_ptr,
        len(data),
        aad_ptr,
        len(aad),
    )

    if res == 0:
        backend._consume_errors()
        raise InvalidTag

    decrypted_data = backend._ffi.buffer(out_buf, out_len[0])[:]
    return decrypted_data
