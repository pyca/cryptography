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
from ...utils import load_nist_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.Blowfish(b"\x00" * 56), modes.ECB()
    ),
    skip_message="Does not support Blowfish ECB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestBlowfishModeECB(object):
    test_ECB = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "Blowfish"),
        ["bf-ecb.txt"],
        lambda key, **kwargs: algorithms.Blowfish(binascii.unhexlify(key)),
        lambda **kwargs: modes.ECB(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.Blowfish(b"\x00" * 56), modes.CBC(b"\x00" * 8)
    ),
    skip_message="Does not support Blowfish CBC",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestBlowfishModeCBC(object):
    test_CBC = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "Blowfish"),
        ["bf-cbc.txt"],
        lambda key, **kwargs: algorithms.Blowfish(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.Blowfish(b"\x00" * 56), modes.OFB(b"\x00" * 8)
    ),
    skip_message="Does not support Blowfish OFB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestBlowfishModeOFB(object):
    test_OFB = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "Blowfish"),
        ["bf-ofb.txt"],
        lambda key, **kwargs: algorithms.Blowfish(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.OFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.Blowfish(b"\x00" * 56), modes.CFB(b"\x00" * 8)
    ),
    skip_message="Does not support Blowfish CFB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestBlowfishModeCFB(object):
    test_CFB = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "Blowfish"),
        ["bf-cfb.txt"],
        lambda key, **kwargs: algorithms.Blowfish(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.CFB(binascii.unhexlify(iv)),
    )
