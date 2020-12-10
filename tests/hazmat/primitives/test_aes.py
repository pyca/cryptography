# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import os

import pytest

from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives.ciphers import algorithms, base, modes

from .utils import _load_all_params, generate_encrypt_test
from ...doubles import DummyMode
from ...utils import load_nist_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES(b"\x00" * 32), modes.XTS(b"\x00" * 16)
    ),
    skip_message="Does not support AES XTS",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestAESModeXTS(object):
    def test_xts_vectors(self, backend, subtests):
        # This list comprehension excludes any vector that does not have a
        # data unit length that is divisible by 8. The NIST vectors include
        # tests for implementations that support encryption of data that is
        # not divisible modulo 8, but OpenSSL is not such an implementation.
        vectors = [
            x
            for x in _load_all_params(
                os.path.join("ciphers", "AES", "XTS", "tweak-128hexstr"),
                ["XTSGenAES128.rsp", "XTSGenAES256.rsp"],
                load_nist_vectors,
            )
            if int(x["dataunitlen"]) / 8.0 == int(x["dataunitlen"]) // 8
        ]
        for vector in vectors:
            with subtests.test():
                key = binascii.unhexlify(vector["key"])
                tweak = binascii.unhexlify(vector["i"])
                pt = binascii.unhexlify(vector["pt"])
                ct = binascii.unhexlify(vector["ct"])
                cipher = base.Cipher(
                    algorithms.AES(key), modes.XTS(tweak), backend
                )
                enc = cipher.encryptor()
                computed_ct = enc.update(pt) + enc.finalize()
                assert computed_ct == ct
                dec = cipher.decryptor()
                computed_pt = dec.update(ct) + dec.finalize()
                assert computed_pt == pt


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES(b"\x00" * 16), modes.CBC(b"\x00" * 16)
    ),
    skip_message="Does not support AES CBC",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestAESModeCBC(object):
    test_cbc = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "AES", "CBC"),
        [
            "CBCGFSbox128.rsp",
            "CBCGFSbox192.rsp",
            "CBCGFSbox256.rsp",
            "CBCKeySbox128.rsp",
            "CBCKeySbox192.rsp",
            "CBCKeySbox256.rsp",
            "CBCVarKey128.rsp",
            "CBCVarKey192.rsp",
            "CBCVarKey256.rsp",
            "CBCVarTxt128.rsp",
            "CBCVarTxt192.rsp",
            "CBCVarTxt256.rsp",
            "CBCMMT128.rsp",
            "CBCMMT192.rsp",
            "CBCMMT256.rsp",
        ],
        lambda key, **kwargs: algorithms.AES(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.CBC(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES(b"\x00" * 16), modes.ECB()
    ),
    skip_message="Does not support AES ECB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestAESModeECB(object):
    test_ecb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "AES", "ECB"),
        [
            "ECBGFSbox128.rsp",
            "ECBGFSbox192.rsp",
            "ECBGFSbox256.rsp",
            "ECBKeySbox128.rsp",
            "ECBKeySbox192.rsp",
            "ECBKeySbox256.rsp",
            "ECBVarKey128.rsp",
            "ECBVarKey192.rsp",
            "ECBVarKey256.rsp",
            "ECBVarTxt128.rsp",
            "ECBVarTxt192.rsp",
            "ECBVarTxt256.rsp",
            "ECBMMT128.rsp",
            "ECBMMT192.rsp",
            "ECBMMT256.rsp",
        ],
        lambda key, **kwargs: algorithms.AES(binascii.unhexlify(key)),
        lambda **kwargs: modes.ECB(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES(b"\x00" * 16), modes.OFB(b"\x00" * 16)
    ),
    skip_message="Does not support AES OFB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestAESModeOFB(object):
    test_ofb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "AES", "OFB"),
        [
            "OFBGFSbox128.rsp",
            "OFBGFSbox192.rsp",
            "OFBGFSbox256.rsp",
            "OFBKeySbox128.rsp",
            "OFBKeySbox192.rsp",
            "OFBKeySbox256.rsp",
            "OFBVarKey128.rsp",
            "OFBVarKey192.rsp",
            "OFBVarKey256.rsp",
            "OFBVarTxt128.rsp",
            "OFBVarTxt192.rsp",
            "OFBVarTxt256.rsp",
            "OFBMMT128.rsp",
            "OFBMMT192.rsp",
            "OFBMMT256.rsp",
        ],
        lambda key, **kwargs: algorithms.AES(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.OFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES(b"\x00" * 16), modes.CFB(b"\x00" * 16)
    ),
    skip_message="Does not support AES CFB",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestAESModeCFB(object):
    test_cfb = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "AES", "CFB"),
        [
            "CFB128GFSbox128.rsp",
            "CFB128GFSbox192.rsp",
            "CFB128GFSbox256.rsp",
            "CFB128KeySbox128.rsp",
            "CFB128KeySbox192.rsp",
            "CFB128KeySbox256.rsp",
            "CFB128VarKey128.rsp",
            "CFB128VarKey192.rsp",
            "CFB128VarKey256.rsp",
            "CFB128VarTxt128.rsp",
            "CFB128VarTxt192.rsp",
            "CFB128VarTxt256.rsp",
            "CFB128MMT128.rsp",
            "CFB128MMT192.rsp",
            "CFB128MMT256.rsp",
        ],
        lambda key, **kwargs: algorithms.AES(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.CFB(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES(b"\x00" * 16), modes.CFB8(b"\x00" * 16)
    ),
    skip_message="Does not support AES CFB8",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestAESModeCFB8(object):
    test_cfb8 = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "AES", "CFB"),
        [
            "CFB8GFSbox128.rsp",
            "CFB8GFSbox192.rsp",
            "CFB8GFSbox256.rsp",
            "CFB8KeySbox128.rsp",
            "CFB8KeySbox192.rsp",
            "CFB8KeySbox256.rsp",
            "CFB8VarKey128.rsp",
            "CFB8VarKey192.rsp",
            "CFB8VarKey256.rsp",
            "CFB8VarTxt128.rsp",
            "CFB8VarTxt192.rsp",
            "CFB8VarTxt256.rsp",
            "CFB8MMT128.rsp",
            "CFB8MMT192.rsp",
            "CFB8MMT256.rsp",
        ],
        lambda key, **kwargs: algorithms.AES(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.CFB8(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.AES(b"\x00" * 16), modes.CTR(b"\x00" * 16)
    ),
    skip_message="Does not support AES CTR",
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
class TestAESModeCTR(object):
    test_ctr = generate_encrypt_test(
        load_nist_vectors,
        os.path.join("ciphers", "AES", "CTR"),
        ["aes-128-ctr.txt", "aes-192-ctr.txt", "aes-256-ctr.txt"],
        lambda key, **kwargs: algorithms.AES(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.CTR(binascii.unhexlify(iv)),
    )


@pytest.mark.parametrize(
    "mode",
    [
        modes.CBC(bytearray(b"\x00" * 16)),
        modes.CTR(bytearray(b"\x00" * 16)),
        modes.OFB(bytearray(b"\x00" * 16)),
        modes.CFB(bytearray(b"\x00" * 16)),
        modes.CFB8(bytearray(b"\x00" * 16)),
        modes.XTS(bytearray(b"\x00" * 16)),
        # Add a dummy mode for coverage of the cipher_supported check.
        DummyMode(),
    ],
)
@pytest.mark.requires_backend_interface(interface=CipherBackend)
def test_buffer_protocol_alternate_modes(mode, backend):
    data = bytearray(b"sixteen_byte_msg")
    key = algorithms.AES(bytearray(os.urandom(32)))
    if not backend.cipher_supported(key, mode):
        pytest.skip("AES in {} mode not supported".format(mode.name))
    cipher = base.Cipher(key, mode, backend)
    enc = cipher.encryptor()
    ct = enc.update(data) + enc.finalize()
    dec = cipher.decryptor()
    pt = dec.update(ct) + dec.finalize()
    assert pt == data
