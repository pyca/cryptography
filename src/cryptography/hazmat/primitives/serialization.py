# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import base64
import struct
import warnings

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers


def load_pem_traditional_openssl_private_key(data, password, backend):
    warnings.warn(
        "load_pem_traditional_openssl_private_key is deprecated and will be "
        "removed in a future version, use load_pem_private_key instead.",
        utils.DeprecatedIn06,
        stacklevel=2
    )

    return backend.load_traditional_openssl_pem_private_key(
        data, password
    )


def load_pem_pkcs8_private_key(data, password, backend):
    warnings.warn(
        "load_pem_pkcs8_private_key is deprecated and will be removed in a "
        "future version, use load_pem_private_key instead.",
        utils.DeprecatedIn06,
        stacklevel=2
    )

    return backend.load_pkcs8_pem_private_key(data, password)


def load_pem_private_key(data, password, backend):
    return backend.load_pem_private_key(data, password)


def load_pem_public_key(data, backend):
    return backend.load_pem_public_key(data)


def load_ssh_public_key(data, backend):
    if not data.startswith(b'ssh-'):
        raise ValueError('SSH-formatted keys must begin with ssh-')

    if not data.startswith(b'ssh-rsa'):
        raise UnsupportedAlgorithm('Only RSA keys are currently supported.')

    return _load_ssh_rsa_public_key(data, backend)


def _load_ssh_rsa_public_key(data, backend):
    assert data.startswith(b'ssh-rsa ')

    parts = data.split(b' ')
    data = base64.b64decode(parts[1])

    cert_data = []

    while len(data) > 0:
        str_len = struct.unpack('>I', data[0:4])[0]
        cert_data.append(data[4:4 + str_len])
        data = data[4 + str_len:]

    e = _bytes_to_int(cert_data[1])
    n = _bytes_to_int(cert_data[2])
    return backend.load_rsa_public_numbers(RSAPublicNumbers(e, n))


def _bytes_to_int(data):
    if len(data) % 4 != 0:
        # Pad the bytes with 0x00 to a block size of 4
        data = (b'\x00' * (4 - (len(data) % 4))) + data

    result = 0

    while len(data) > 0:
        result = (result << 32) + struct.unpack('>I', data[0:4])[0]
        data = data[4:]

    return result
