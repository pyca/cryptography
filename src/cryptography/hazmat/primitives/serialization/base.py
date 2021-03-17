# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import typing

from cryptography.hazmat._types import (
    _PRIVATE_KEY_TYPES,
    _PUBLIC_KEY_TYPES,
)
from cryptography.hazmat.backends import _get_backend
<<<<<<< HEAD
from cryptography.hazmat.backends.interfaces import Backend
=======
>>>>>>> b813e816e2871e5f9ab2f101ee94713f8b3e95b0
from cryptography.hazmat.primitives.asymmetric import dh


def load_pem_private_key(
<<<<<<< HEAD
    data: bytes,
    password: typing.Optional[bytes],
    backend: typing.Optional[Backend] = None,
=======
    data: bytes, password: typing.Optional[bytes], backend=None
>>>>>>> b813e816e2871e5f9ab2f101ee94713f8b3e95b0
) -> _PRIVATE_KEY_TYPES:
    backend = _get_backend(backend)
    return backend.load_pem_private_key(data, password)


<<<<<<< HEAD
def load_pem_public_key(
    data: bytes, backend: typing.Optional[Backend] = None
) -> _PUBLIC_KEY_TYPES:
=======
def load_pem_public_key(data: bytes, backend=None) -> _PUBLIC_KEY_TYPES:
>>>>>>> b813e816e2871e5f9ab2f101ee94713f8b3e95b0
    backend = _get_backend(backend)
    return backend.load_pem_public_key(data)


<<<<<<< HEAD
def load_pem_parameters(
    data: bytes, backend: typing.Optional[Backend] = None
) -> "dh.DHParameters":
=======
def load_pem_parameters(data: bytes, backend=None) -> "dh.DHParameters":
>>>>>>> b813e816e2871e5f9ab2f101ee94713f8b3e95b0
    backend = _get_backend(backend)
    return backend.load_pem_parameters(data)


def load_der_private_key(
<<<<<<< HEAD
    data: bytes,
    password: typing.Optional[bytes],
    backend: typing.Optional[Backend] = None,
=======
    data: bytes, password: typing.Optional[bytes], backend=None
>>>>>>> b813e816e2871e5f9ab2f101ee94713f8b3e95b0
) -> _PRIVATE_KEY_TYPES:
    backend = _get_backend(backend)
    return backend.load_der_private_key(data, password)


<<<<<<< HEAD
def load_der_public_key(
    data: bytes, backend: typing.Optional[Backend] = None
) -> _PUBLIC_KEY_TYPES:
=======
def load_der_public_key(data: bytes, backend=None) -> _PUBLIC_KEY_TYPES:
>>>>>>> b813e816e2871e5f9ab2f101ee94713f8b3e95b0
    backend = _get_backend(backend)
    return backend.load_der_public_key(data)


<<<<<<< HEAD
def load_der_parameters(
    data: bytes, backend: typing.Optional[Backend] = None
) -> "dh.DHParameters":
=======
def load_der_parameters(data: bytes, backend=None) -> "dh.DHParameters":
>>>>>>> b813e816e2871e5f9ab2f101ee94713f8b3e95b0
    backend = _get_backend(backend)
    return backend.load_der_parameters(data)
