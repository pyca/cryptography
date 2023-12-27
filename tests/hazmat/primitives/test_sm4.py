# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii
import os

import pytest

from cryptography.hazmat.primitives.ciphers import algorithms, base, modes

from ...utils import load_nist_vectors
from .utils import generate_encrypt_test


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
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify(key)),
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
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify(key)),
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
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify(key)),
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
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify(key)),
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
        lambda key, **kwargs: algorithms.SM4(binascii.unhexlify(key)),
        lambda iv, **kwargs: modes.CTR(binascii.unhexlify(iv)),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.cipher_supported(
        algorithms.SM4(b"\x00" * 16), modes.GCM(b"\x00" * 16)
    ),
    skip_message="Does not support SM4 GCM",
)
class TestSM4ModeGCM:
    def test_gcm(self, backend):
        # test vectors from RFC 8998 Appendix A.1
        key = binascii.unhexlify("0123456789ABCDEFFEDCBA9876543210")
        iv = binascii.unhexlify("00001234567800000000ABCD")
        associated_data = binascii.unhexlify(
            "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2",
        )
        plaintext = binascii.unhexlify(
            "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
            "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
            "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF"
            "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA"
        )
        ciphertext = binascii.unhexlify(
            "17F399F08C67D5EE19D0DC9969C4BB7D"
            "5FD46FD3756489069157B282BB200735"
            "D82710CA5C22F0CCFA7CBF93D496AC15"
            "A56834CBCF98C397B4024A2691233B8D"
        )
        tag = binascii.unhexlify("83DE3541E4C2B58177E065A9BF7B62EC")

        cipher = base.Cipher(
            algorithms.SM4(key), modes.GCM(iv), backend=backend
        )
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(associated_data)
        computed_ciphertext = (
            encryptor.update(plaintext) + encryptor.finalize()
        )
        assert computed_ciphertext == ciphertext
        assert encryptor.tag == tag

    def test_gcm_decrypt(self, backend):
        # test vectors from RFC 8998 Appendix A.1
        key = binascii.unhexlify("0123456789ABCDEFFEDCBA9876543210")
        iv = binascii.unhexlify("00001234567800000000ABCD")
        associated_data = binascii.unhexlify(
            "FEEDFACEDEADBEEFFEEDFACEDEADBEEFABADDAD2"
        )
        plaintext = binascii.unhexlify(
            "AAAAAAAAAAAAAAAABBBBBBBBBBBBBBBB"
            "CCCCCCCCCCCCCCCCDDDDDDDDDDDDDDDD"
            "EEEEEEEEEEEEEEEEFFFFFFFFFFFFFFFF"
            "EEEEEEEEEEEEEEEEAAAAAAAAAAAAAAAA"
        )
        ciphertext = binascii.unhexlify(
            "17F399F08C67D5EE19D0DC9969C4BB7D"
            "5FD46FD3756489069157B282BB200735"
            "D82710CA5C22F0CCFA7CBF93D496AC15"
            "A56834CBCF98C397B4024A2691233B8D"
        )
        tag = binascii.unhexlify("83DE3541E4C2B58177E065A9BF7B62EC")

        cipher = base.Cipher(
            algorithms.SM4(key), modes.GCM(iv, tag), backend=backend
        )
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(associated_data)
        computed_plaintext = (
            decryptor.update(ciphertext) + decryptor.finalize()
        )
        assert computed_plaintext == plaintext
