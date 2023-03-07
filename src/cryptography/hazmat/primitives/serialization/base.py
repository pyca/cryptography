# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import typing
import warnings

from cryptography import utils
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.types import (
    PRIVATE_KEY_TYPES,
    PUBLIC_KEY_TYPES,
)

_SENTINEL = object()


def load_pem_private_key(
    data: bytes,
    password: typing.Optional[bytes],
    backend: typing.Any = None,
    *,
    unsafe_skip_rsa_key_validation=_SENTINEL,
    unsafe_skip_key_validation: bool = False,
) -> PRIVATE_KEY_TYPES:
    from cryptography.hazmat.backends.openssl.backend import backend as ossl

    if unsafe_skip_rsa_key_validation is not _SENTINEL:
        warnings.warn(
            "unsafe_skip_rsa_key_validation is deprecated and will be removed "
            "in 42.0.0. Please use unsafe_skip_key_validation instead.",
            utils.DeprecatedIn40,
            stacklevel=2,
        )
        unsafe_skip_key_validation = unsafe_skip_rsa_key_validation

    return ossl.load_pem_private_key(
        data, password, unsafe_skip_key_validation
    )


def load_pem_public_key(
    data: bytes,
    backend: typing.Any = None,
    *,
    unsafe_skip_key_validation: bool = False,
) -> PUBLIC_KEY_TYPES:
    from cryptography.hazmat.backends.openssl.backend import backend as ossl

    return ossl.load_pem_public_key(
        data, unsafe_skip_key_validation=unsafe_skip_key_validation
    )


def load_pem_parameters(
    data: bytes, backend: typing.Any = None
) -> "dh.DHParameters":
    from cryptography.hazmat.backends.openssl.backend import backend as ossl

    return ossl.load_pem_parameters(data)


def load_der_private_key(
    data: bytes,
    password: typing.Optional[bytes],
    backend: typing.Any = None,
    *,
    unsafe_skip_rsa_key_validation=_SENTINEL,
    unsafe_skip_key_validation: bool = False,
) -> PRIVATE_KEY_TYPES:
    from cryptography.hazmat.backends.openssl.backend import backend as ossl

    if unsafe_skip_rsa_key_validation is not _SENTINEL:
        warnings.warn(
            "unsafe_skip_rsa_key_validation is deprecated and will be removed "
            "in 42.0.0. Please use unsafe_skip_key_validation instead.",
            utils.DeprecatedIn40,
            stacklevel=2,
        )
        unsafe_skip_key_validation = unsafe_skip_rsa_key_validation

    return ossl.load_der_private_key(
        data, password, unsafe_skip_key_validation
    )


def load_der_public_key(
    data: bytes,
    backend: typing.Any = None,
    *,
    unsafe_skip_key_validation: bool = False,
) -> PUBLIC_KEY_TYPES:
    from cryptography.hazmat.backends.openssl.backend import backend as ossl

    return ossl.load_der_public_key(
        data, unsafe_skip_key_validation=unsafe_skip_key_validation
    )


def load_der_parameters(
    data: bytes, backend: typing.Any = None
) -> "dh.DHParameters":
    from cryptography.hazmat.backends.openssl.backend import backend as ossl

    return ossl.load_der_parameters(data)
