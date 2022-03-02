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
        algorithms._SEEDInternal(b"\x00" * 16), modes.ECB()
    ),
    skip_message="Does not support SEED ECB",
)
class TestSEEDModeECB:
    test_ecb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SEED"),
        ["rfc-4269.txt"],
        lambda key, **kwargs: algorithms._SEEDInternal(
            binascii.unhexlify((key))
        ),
        lambda **kwargs: modes.ECB(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms._SEEDInternal(b"\x00" * 16), modes.CBC(b"\x00" * 16)
    ),
    skip_message="Does not support SEED CBC",
)
class TestSEEDModeCBC:
    test_cbc = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SEED"),
        ["rfc-4196.txt"],
        lambda key, **kwargs: algorithms._SEEDInternal(
            binascii.unhexlify((key))
        ),
        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms._SEEDInternal(b"\x00" * 16), modes.OFB(b"\x00" * 16)
    ),
    skip_message="Does not support SEED OFB",
)
class TestSEEDModeOFB:
    test_ofb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SEED"),
        ["seed-ofb.txt"],
        lambda key, **kwargs: algorithms._SEEDInternal(
            binascii.unhexlify((key))
        ),
        lambda iv, **kwargs: modes.OFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms._SEEDInternal(b"\x00" * 16), modes.CFB(b"\x00" * 16)
    ),
    skip_message="Does not support SEED CFB",
)
class TestSEEDModeCFB:
    test_cfb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SEED"),
        ["seed-cfb.txt"],
        lambda key, **kwargs: algorithms._SEEDInternal(
            binascii.unhexlify((key))
        ),
        lambda iv, **kwargs: modes.CFB(binascii.unhexlify(iv)),
    )
