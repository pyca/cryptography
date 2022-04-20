# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import os

import pytest

from cryptography.hazmat.primitives.ciphers import algorithms, modes

from .utils import generate_encrypt_test
from ...utils import load_nist_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms._BlowfishInternal(b"\x00" * 56), modes.ECB()
    ),
    skip_message="Does not support Blowfish ECB",
)
class TestBlowfishModeECB:
    test_ecb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "Blowfish"),
        ["bf-ecb.txt"],
        lambda key, **kwargs: algorithms._BlowfishInternal(
            binascii.unhexlify(key)
        ),
        lambda **kwargs: modes.ECB(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms._BlowfishInternal(b"\x00" * 56), modes.CBC(b"\x00" * 8)
    ),
    skip_message="Does not support Blowfish CBC",
)
class TestBlowfishModeCBC:
    test_cbc = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "Blowfish"),
        ["bf-cbc.txt"],
        lambda key, **kwargs: algorithms._BlowfishInternal(
            binascii.unhexlify(key)
        ),
        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms._BlowfishInternal(b"\x00" * 56), modes.OFB(b"\x00" * 8)
    ),
    skip_message="Does not support Blowfish OFB",
)
class TestBlowfishModeOFB:
    test_ofb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "Blowfish"),
        ["bf-ofb.txt"],
        lambda key, **kwargs: algorithms._BlowfishInternal(
            binascii.unhexlify(key)
        ),
        lambda iv, **kwargs: modes.OFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms._BlowfishInternal(b"\x00" * 56), modes.CFB(b"\x00" * 8)
    ),
    skip_message="Does not support Blowfish CFB",
)
class TestBlowfishModeCFB:
    test_cfb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "Blowfish"),
        ["bf-cfb.txt"],
        lambda key, **kwargs: algorithms._BlowfishInternal(
            binascii.unhexlify(key)
        ),
        lambda iv, **kwargs: modes.CFB(binascii.unhexlify(iv)),
    )
