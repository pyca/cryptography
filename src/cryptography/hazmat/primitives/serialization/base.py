# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import typing

from cryptography.hazmat.backends import _get_backend
from cryptography.hazmat.backends.interfaces import Backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.asymmetric.types import (
    PRIVATE_KEY_TYPES,
    PUBLIC_KEY_TYPES,
)


def load_pem_private_key(
    data: bytes,
    password: typing.Optional[bytes],
    backend: typing.Optional[Backend] = None,
) -> PRIVATE_KEY_TYPES:
    backend = _get_backend(backend)
    return backend.load_pem_private_key(data, password)


def load_pem_public_key(
    data: bytes, backend: typing.Optional[Backend] = None
) -> PUBLIC_KEY_TYPES:
    backend = _get_backend(backend)
    return backend.load_pem_public_key(data)


def load_pem_parameters(
    data: bytes, backend: typing.Optional[Backend] = None
) -> "dh.DHParameters":
    backend = _get_backend(backend)
    return backend.load_pem_parameters(data)


def load_der_private_key(
    data: bytes,
    password: typing.Optional[bytes],
    backend: typing.Optional[Backend] = None,
) -> PRIVATE_KEY_TYPES:
    backend = _get_backend(backend)
    return backend.load_der_private_key(data, password)


def load_der_public_key(
    data: bytes, backend: typing.Optional[Backend] = None
) -> PUBLIC_KEY_TYPES:
    backend = _get_backend(backend)
    return backend.load_der_public_key(data)


def load_der_parameters(
    data: bytes, backend: typing.Optional[Backend] = None
) -> "dh.DHParameters":
    backend = _get_backend(backend)
    return backend.load_der_parameters(data)
