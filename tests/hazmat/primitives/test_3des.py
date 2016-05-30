# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

"""
Test using the NIST Test Vectors
"""

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
        algorithms.TripleDES(b"\x00" * 8), modes.CBC(b"\x00" * 8)
    ),
    skip_message="Does not support TripleDES CBC",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestTripleDESModeCBC(object):
    test_KAT = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "3DES", "CBC"),
        [
            "TCBCinvperm.rsp",
            "TCBCpermop.rsp",
            "TCBCsubtab.rsp",
            "TCBCvarkey.rsp",
            "TCBCvartext.rsp",
        ],
        lambda keys, **kwargs: algorithms.TripleDES(binascii.unhexlify(keys)),
        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv)),
    )

    test_MMT = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "3DES", "CBC"),
        [
            "TCBCMMT1.rsp",
            "TCBCMMT2.rsp",
            "TCBCMMT3.rsp",
        ],
        lambda key1, key2, key3, **kwargs: algorithms.TripleDES(
            binascii.unhexlify(key1 + key2 + key3)
        ),
        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.TripleDES(b"\x00" * 8), modes.OFB(b"\x00" * 8)
    ),
    skip_message="Does not support TripleDES OFB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestTripleDESModeOFB(object):
    test_KAT = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "3DES", "OFB"),
        [
            "TOFBpermop.rsp",
            "TOFBsubtab.rsp",
            "TOFBvarkey.rsp",
            "TOFBvartext.rsp",
            "TOFBinvperm.rsp",
        ],
        lambda keys, **kwargs: algorithms.TripleDES(binascii.unhexlify(keys)),
        lambda iv, **kwargs: modes.OFB(binascii.unhexlify(iv)),
    )

    test_MMT = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "3DES", "OFB"),
        [
            "TOFBMMT1.rsp",
            "TOFBMMT2.rsp",
            "TOFBMMT3.rsp",
        ],
        lambda key1, key2, key3, **kwargs: algorithms.TripleDES(
            binascii.unhexlify(key1 + key2 + key3)
        ),
        lambda iv, **kwargs: modes.OFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.TripleDES(b"\x00" * 8), modes.CFB(b"\x00" * 8)
    ),
    skip_message="Does not support TripleDES CFB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestTripleDESModeCFB(object):
    test_KAT = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "3DES", "CFB"),
        [
            "TCFB64invperm.rsp",
            "TCFB64permop.rsp",
            "TCFB64subtab.rsp",
            "TCFB64varkey.rsp",
            "TCFB64vartext.rsp",
        ],
        lambda keys, **kwargs: algorithms.TripleDES(binascii.unhexlify(keys)),
        lambda iv, **kwargs: modes.CFB(binascii.unhexlify(iv)),
    )

    test_MMT = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "3DES", "CFB"),
        [
            "TCFB64MMT1.rsp",
            "TCFB64MMT2.rsp",
            "TCFB64MMT3.rsp",
        ],
        lambda key1, key2, key3, **kwargs: algorithms.TripleDES(
            binascii.unhexlify(key1 + key2 + key3)
        ),
        lambda iv, **kwargs: modes.CFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.TripleDES(b"\x00" * 8), modes.CFB8(b"\x00" * 8)
    ),
    skip_message="Does not support TripleDES CFB8",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestTripleDESModeCFB8(object):
    test_KAT = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "3DES", "CFB"),
        [
            "TCFB8invperm.rsp",
            "TCFB8permop.rsp",
            "TCFB8subtab.rsp",
            "TCFB8varkey.rsp",
            "TCFB8vartext.rsp",
        ],
        lambda keys, **kwargs: algorithms.TripleDES(binascii.unhexlify(keys)),
        lambda iv, **kwargs: modes.CFB8(binascii.unhexlify(iv)),
    )

    test_MMT = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "3DES", "CFB"),
        [
            "TCFB8MMT1.rsp",
            "TCFB8MMT2.rsp",
            "TCFB8MMT3.rsp",
        ],
        lambda key1, key2, key3, **kwargs: algorithms.TripleDES(
            binascii.unhexlify(key1 + key2 + key3)
        ),
        lambda iv, **kwargs: modes.CFB8(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.TripleDES("\x00" * 8), modes.ECB()
    ),
    skip_message="Does not support TripleDES ECB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestTripleDESModeECB(object):
    test_KAT = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "3DES", "ECB"),
        [
            "TECBinvperm.rsp",
            "TECBpermop.rsp",
            "TECBsubtab.rsp",
            "TECBvarkey.rsp",
            "TECBvartext.rsp",
        ],
        lambda keys, **kwargs: algorithms.TripleDES(binascii.unhexlify(keys)),
        lambda **kwargs: modes.ECB(),
    )

    test_MMT = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "3DES", "ECB"),
        [
            "TECBMMT1.rsp",
            "TECBMMT2.rsp",
            "TECBMMT3.rsp",
        ],
        lambda key1, key2, key3, **kwargs: algorithms.TripleDES(
            binascii.unhexlify(key1 + key2 + key3)
        ),
        lambda **kwargs: modes.ECB(),
    )
