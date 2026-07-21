# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import hashlib
import typing
import zlib

import pytest

from cryptography.cobblestone import (
    Cobblestone128Decryptor,
    Cobblestone256Decryptor,
)
from cryptography.exceptions import AlreadyFinalized, InvalidTag

from .utils import wycheproof_tests

_DECRYPTORS: dict[str, typing.Any] = {
    "AEAD_AES_128_GCM": Cobblestone128Decryptor,
    "AEAD_AES_256_GCM": Cobblestone256Decryptor,
}


@wycheproof_tests(
    "c2sp_chunked_encryption_aes_128_gcm_test.json",
    "c2sp_chunked_encryption_aes_256_gcm_test.json",
)
def test_cobblestone(backend, wycheproof):
    assert wycheproof.testgroup["sha"] == "SHA-512"
    decryptor_cls = _DECRYPTORS[wycheproof.testgroup["aead"]]
    key = binascii.unhexlify(wycheproof.testcase["key"])
    ctx = binascii.unhexlify(wycheproof.testcase["ctx"])
    ct = zlib.decompress(binascii.unhexlify(wycheproof.testcase["ct"]))

    if wycheproof.valid:
        dec = decryptor_cls(key, ctx)
        msg = dec.update(ct) + dec.finalize()
        assert len(msg) == wycheproof.testcase["msgLength"]
        assert (
            hashlib.sha512(msg).hexdigest() == wycheproof.testcase["msgSha512"]
        )
    elif wycheproof.has_flag("InvalidKeySize"):
        with pytest.raises(ValueError):
            decryptor_cls(key, ctx)
    else:
        dec = decryptor_cls(key, ctx)
        with pytest.raises(InvalidTag):
            dec.update(ct)
            dec.finalize()
        # The failed context must keep failing rather than report a clean
        # end of message.
        with pytest.raises((InvalidTag, AlreadyFinalized)):
            dec.finalize()
