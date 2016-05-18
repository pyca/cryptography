# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii
import os

import pytest

from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives.ciphers import algorithms, modes

from .utils import generate_encrypt_test
from ...utils import (
    load_cryptrec_vectors, load_nist_vectors
)


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.Camellia(b"\x00" * 16), modes.ECB()
    ),
    skip_message="Does not support Camellia ECB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestCamelliaModeECB(object):
    test_ECB = generate_encrypt_test(
        load_cryptrec_vectors,
        os.path.join("ciphers", "Camellia"),
        [
            "camellia-128-ecb.txt",
            "camellia-192-ecb.txt",
            "camellia-256-ecb.txt"
        ],
        lambda key, **kwargs: algorithms.Camellia(binascii.unhexlify(key)),
        lambda **kwargs: modes.ECB(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.Camellia(b"\x00" * 16), modes.CBC(b"\x00" * 16)
    ),
    skip_message="Does not support Camellia CBC",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestCamelliaModeCBC(object):
    test_CBC = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "Camellia"),
        ["camellia-cbc.txt"],
        lambda key, **kwargs: algorithms.Camellia(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.Camellia(b"\x00" * 16), modes.OFB(b"\x00" * 16)
    ),
    skip_message="Does not support Camellia OFB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestCamelliaModeOFB(object):
    test_OFB = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "Camellia"),
        ["camellia-ofb.txt"],
        lambda key, **kwargs: algorithms.Camellia(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.OFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.Camellia(b"\x00" * 16), modes.CFB(b"\x00" * 16)
    ),
    skip_message="Does not support Camellia CFB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestCamelliaModeCFB(object):
    test_CFB = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "Camellia"),
        ["camellia-cfb.txt"],
        lambda key, **kwargs: algorithms.Camellia(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.CFB(binascii.unhexlify(iv)),
    )
