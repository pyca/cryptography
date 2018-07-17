# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii

import pytest

from cryptography.hazmat.backends.interfaces import CipherBackend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)


@pytest.mark.requires_backend_interface(interface=CipherBackend)
@pytest.mark.wycheproof_tests("aes_cbc_pkcs5_test.json")
def test_aes_cbc_pkcs5(backend, wycheproof):
    key = binascii.unhexlify(wycheproof.testcase["key"])
    iv = binascii.unhexlify(wycheproof.testcase["iv"])
    msg = binascii.unhexlify(wycheproof.testcase["msg"])
    ct = binascii.unhexlify(wycheproof.testcase["ct"])

    padder = padding.PKCS7(128).padder()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend)
    enc = cipher.encryptor()
    computed_ct = enc.update(
        padder.update(msg) + padder.finalize()) + enc.finalize()
    dec = cipher.decryptor()
    padded_msg = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    if wycheproof.valid or wycheproof.acceptable:
        assert computed_ct == ct
        computed_msg = unpadder.update(padded_msg) + unpadder.finalize()
        assert computed_msg == msg
    else:
        assert computed_ct != ct
        with pytest.raises(ValueError):
            unpadder.update(padded_msg) + unpadder.finalize()
