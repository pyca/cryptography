# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import abc
import typing
from enum import Enum

from cryptography import utils
from cryptography.hazmat.backends import _get_backend
from cryptography.hazmat.primitives.asymmetric import dh

if typing.TYPE_CHECKING:  # pragma: no cover
    from cryptography.x509.base import _PRIVATE_KEY_TYPES, _PUBLIC_KEY_TYPES


def load_pem_private_key(
    data: bytes, password: typing.Optional[bytes], backend=None
) -> "_PRIVATE_KEY_TYPES":
    backend = _get_backend(backend)
    return backend.load_pem_private_key(data, password)


def load_pem_public_key(data: bytes, backend=None) -> "_PUBLIC_KEY_TYPES":
    backend = _get_backend(backend)
    return backend.load_pem_public_key(data)


def load_pem_parameters(data: bytes, backend=None) -> dh.DHParameters:
    backend = _get_backend(backend)
    return backend.load_pem_parameters(data)


def load_der_private_key(
    data: bytes, password: typing.Optional[bytes], backend=None
) -> "_PRIVATE_KEY_TYPES":
    backend = _get_backend(backend)
    return backend.load_der_private_key(data, password)


def load_der_public_key(data: bytes, backend=None) -> "_PUBLIC_KEY_TYPES":
    backend = _get_backend(backend)
    return backend.load_der_public_key(data)


def load_der_parameters(data: bytes, backend=None) -> dh.DHParameters:
    backend = _get_backend(backend)
    return backend.load_der_parameters(data)


class Encoding(Enum):
    PEM = "PEM"
    DER = "DER"
    OpenSSH = "OpenSSH"
    Raw = "Raw"
    X962 = "ANSI X9.62"
    SMIME = "S/MIME"


class PrivateFormat(Enum):
    PKCS8 = "PKCS8"
    TraditionalOpenSSL = "TraditionalOpenSSL"
    Raw = "Raw"
    OpenSSH = "OpenSSH"


class PublicFormat(Enum):
    SubjectPublicKeyInfo = "X.509 subjectPublicKeyInfo with PKCS#1"
    PKCS1 = "Raw PKCS#1"
    OpenSSH = "OpenSSH"
    Raw = "Raw"
    CompressedPoint = "X9.62 Compressed Point"
    UncompressedPoint = "X9.62 Uncompressed Point"


class ParameterFormat(Enum):
    PKCS3 = "PKCS3"


class KeySerializationEncryption(metaclass=abc.ABCMeta):
    pass


class BestAvailableEncryption(KeySerializationEncryption):
    def __init__(self, password: bytes):
        if not isinstance(password, bytes) or len(password) == 0:
            raise ValueError("Password must be 1 or more bytes.")

        self.password = password


class NoEncryption(KeySerializationEncryption):
    pass
