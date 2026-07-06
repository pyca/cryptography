# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import typing

import pytest

from cryptography.exceptions import (
    AlreadyFinalized,
    InvalidSignature,
    _Reasons,
)
from cryptography.hazmat.primitives import hashes, hmac

from ...doubles import DummyHashAlgorithm
from ...utils import raises_unsupported_algorithm
from .utils import generate_base_hmac_test


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.MD5()),
    skip_message="Does not support MD5",
)
class TestHMACCopy:
    test_copy = generate_base_hmac_test(
        hashes.MD5(),
    )


class TestHMAC:
    def test_hmac_reject_unicode(self):
        h = hmac.HMAC(b"mykey", hashes.SHA1())
        with pytest.raises(TypeError):
            h.update(typing.cast(typing.Any, "\u00fc"))

    def test_hmac_algorithm_instance(self):
        with pytest.raises(TypeError):
            hmac.HMAC(b"key", typing.cast(typing.Any, hashes.SHA1))

    def test_raises_after_finalize(self):
        h = hmac.HMAC(b"key", hashes.SHA1())
        h.finalize()

        with pytest.raises(AlreadyFinalized):
            h.update(b"foo")

        with pytest.raises(AlreadyFinalized):
            h.copy()

        with pytest.raises(AlreadyFinalized):
            h.finalize()

    def test_verify(self):
        h = hmac.HMAC(b"", hashes.SHA1())
        digest = h.finalize()

        h = hmac.HMAC(b"", hashes.SHA1())
        h.verify(digest)

        with pytest.raises(AlreadyFinalized):
            h.verify(b"")

    def test_invalid_verify(self):
        h = hmac.HMAC(b"", hashes.SHA1())
        with pytest.raises(InvalidSignature):
            h.verify(b"")

        with pytest.raises(AlreadyFinalized):
            h.verify(b"")

    def test_verify_reject_unicode(self):
        h = hmac.HMAC(b"", hashes.SHA1())
        with pytest.raises(TypeError):
            h.verify(typing.cast(typing.Any, ""))

    def test_unsupported_hash(self):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            hmac.HMAC(b"key", DummyHashAlgorithm())

        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            hmac.HMAC(b"key", hashes.SHAKE256(digest_size=256))

    def test_buffer_protocol(self):
        key = bytearray(b"2b7e151628aed2a6abf7158809cf4f3c")
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(bytearray(b"6bc1bee22e409f96e93d7e117393172a"))
        assert h.finalize() == binascii.unhexlify(
            b"a1bf7169c56a501c6585190ff4f07cad6e492a3ee187c0372614fb444b9fc3f0"
        )

    def test_algorithm(self):
        alg = hashes.SHA256()
        h = hmac.HMAC(b"123456", alg)
        assert h.algorithm is alg
