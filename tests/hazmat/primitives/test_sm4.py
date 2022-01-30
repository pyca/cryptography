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
        algorithms.SM4(b"\x00" * 16), modes.ECB()
    ),
    skip_message="Does not support SM4 ECB",
)
class TestSM4ModeECB:
    test_ecb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SM4"),
        ["draft-ribose-cfrg-sm4-10-ecb.txt"],
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify((key))),
        lambda **kwargs: modes.ECB(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.SM4(b"\x00" * 16), modes.CBC(b"\x00" * 16)
    ),
    skip_message="Does not support SM4 CBC",
)
class TestSM4ModeCBC:
    test_cbc = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SM4"),
        ["draft-ribose-cfrg-sm4-10-cbc.txt"],
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify((key))),
        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.SM4(b"\x00" * 16), modes.OFB(b"\x00" * 16)
    ),
    skip_message="Does not support SM4 OFB",
)
class TestSM4ModeOFB:
    test_ofb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SM4"),
        ["draft-ribose-cfrg-sm4-10-ofb.txt"],
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify((key))),
        lambda iv, **kwargs: modes.OFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.SM4(b"\x00" * 16), modes.CFB(b"\x00" * 16)
    ),
    skip_message="Does not support SM4 CFB",
)
class TestSM4ModeCFB:
    test_cfb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SM4"),
        ["draft-ribose-cfrg-sm4-10-cfb.txt"],
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify((key))),
        lambda iv, **kwargs: modes.CFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.SM4(b"\x00" * 16), modes.CTR(b"\x00" * 16)
    ),
    skip_message="Does not support SM4 CTR",
)
class TestSM4ModeCTR:
    test_cfb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "SM4"),
        ["draft-ribose-cfrg-sm4-10-ctr.txt"],
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify((key))),
        lambda iv, **kwargs: modes.CTR(binascii.unhexlify(iv)),
    )
