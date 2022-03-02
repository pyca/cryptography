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
        algorithms._CAST5Internal(b"\x00" * 16), modes.ECB()
    ),
    skip_message="Does not support CAST5 ECB",
)
class TestCAST5ModeECB:
    test_ecb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "CAST5"),
        ["cast5-ecb.txt"],
        lambda key, **kwargs: algorithms._CAST5Internal(
            binascii.unhexlify((key))
        ),
        lambda **kwargs: modes.ECB(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms._CAST5Internal(b"\x00" * 16), modes.CBC(b"\x00" * 8)
    ),
    skip_message="Does not support CAST5 CBC",
)
class TestCAST5ModeCBC:
    test_cbc = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "CAST5"),
        ["cast5-cbc.txt"],
        lambda key, **kwargs: algorithms._CAST5Internal(
            binascii.unhexlify((key))
        ),
        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms._CAST5Internal(b"\x00" * 16), modes.OFB(b"\x00" * 8)
    ),
    skip_message="Does not support CAST5 OFB",
)
class TestCAST5ModeOFB:
    test_ofb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "CAST5"),
        ["cast5-ofb.txt"],
        lambda key, **kwargs: algorithms._CAST5Internal(
            binascii.unhexlify((key))
        ),
        lambda iv, **kwargs: modes.OFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms._CAST5Internal(b"\x00" * 16), modes.CFB(b"\x00" * 8)
    ),
    skip_message="Does not support CAST5 CFB",
)
class TestCAST5ModeCFB:
    test_cfb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "CAST5"),
        ["cast5-cfb.txt"],
        lambda key, **kwargs: algorithms._CAST5Internal(
            binascii.unhexlify((key))
        ),
        lambda iv, **kwargs: modes.CFB(binascii.unhexlify(iv)),
    )
