# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import typing

if typing.TYPE_CHECKING:
    from cryptography.hazmat.backends.openssl.backend import Backend
    from cryptography.hazmat.primitives.ciphers.aead import (
        AESCCM,
        AESGCM,
        AESOCB3,
        AESSIV,
        ChaCha20Poly1305,
    )

    _AEADTypes = typing.Union[
        AESCCM, AESGCM, AESOCB3, AESSIV, ChaCha20Poly1305
    ]


def _is_boringssl_supported_cipher(
    backend: Backend, cipher: _AEADTypes
) -> bool:
    """Check if cipher is ChaCha20Poly1305 and backend is BoringSSL

    ChaCha20Poly1305 is supported in BoringSSL through a different API than
    OpenSSL, so there is a separate code path for it
    """
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    return backend._lib.CRYPTOGRAPHY_IS_BORINGSSL and isinstance(
        cipher, ChaCha20Poly1305
    )


def aead_cipher_supported(backend: Backend, cipher: _AEADTypes) -> bool:
    if _is_boringssl_supported_cipher(backend, cipher):
        return True
    else:
        from cryptography.hazmat.backends.openssl.aead._aead_openssl import (
            _aead_cipher_name,
        )

        cipher_name = _aead_cipher_name(cipher)
        if backend._fips_enabled and cipher_name not in backend._fips_aead:
            return False
        # SIV isn't loaded through get_cipherbyname but instead a new fetch API
        # only available in 3.0+. But if we know we're on 3.0+ then we know
        # it's supported.
        if cipher_name.endswith(b"-siv"):
            return backend._lib.CRYPTOGRAPHY_OPENSSL_300_OR_GREATER == 1
        else:
            return (
                backend._lib.EVP_get_cipherbyname(cipher_name)
                != backend._ffi.NULL
            )


def _aead_create_ctx(
    backend: Backend,
    cipher: _AEADTypes,
    key: bytes,
):
    if _is_boringssl_supported_cipher(backend, cipher):
        from cryptography.hazmat.backends.openssl.aead._aead_boringssl import (
            _aead_create_ctx as create_ctx_boring,
        )

        return create_ctx_boring(backend, cipher, key)
    else:
        from cryptography.hazmat.backends.openssl.aead._aead_openssl import (
            _aead_create_ctx as create_ctx_openssl,
        )

        return create_ctx_openssl(backend, cipher, key)


def _encrypt(
    backend: Backend,
    cipher: _AEADTypes,
    nonce: bytes,
    data: bytes,
    associated_data: typing.List[bytes],
    tag_length: int,
    ctx: typing.Any = None,
) -> bytes:
    if _is_boringssl_supported_cipher(backend, cipher):
        from cryptography.hazmat.backends.openssl.aead._aead_boringssl import (
            _encrypt,
        )

        return _encrypt(
            backend, cipher, nonce, data, associated_data, tag_length, ctx
        )
    else:
        from cryptography.hazmat.backends.openssl.aead._aead_openssl import (
            _encrypt,
        )

        return _encrypt(
            backend, cipher, nonce, data, associated_data, tag_length, ctx
        )


def _decrypt(
    backend: Backend,
    cipher: _AEADTypes,
    nonce: bytes,
    data: bytes,
    associated_data: typing.List[bytes],
    tag_length: int,
    ctx: typing.Any = None,
) -> bytes:
    if _is_boringssl_supported_cipher(backend, cipher):
        from cryptography.hazmat.backends.openssl.aead._aead_boringssl import (
            _decrypt,
        )

        return _decrypt(
            backend, cipher, nonce, data, associated_data, tag_length, ctx
        )
    else:
        from cryptography.hazmat.backends.openssl.aead._aead_openssl import (
            _decrypt,
        )

        return _decrypt(
            backend, cipher, nonce, data, associated_data, tag_length, ctx
        )
