# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import sys
import typing

import pytest

from cryptography.exceptions import AlreadyFinalized, InvalidKey
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.concatkdf import (
    ConcatKDFHash,
    ConcatKDFHMAC,
)


class TestConcatKDFHash:
    def test_length_limit(self):
        big_length = hashes.SHA256().digest_size * (2**32 - 1) + 1
        error = OverflowError if sys.maxsize <= 2**31 else ValueError

        with pytest.raises(error):
            ConcatKDFHash(hashes.SHA256(), big_length, None)

    def test_already_finalized(self):
        ckdf = ConcatKDFHash(hashes.SHA256(), 16, None)

        ckdf.derive(b"\x01" * 16)

        with pytest.raises(AlreadyFinalized):
            ckdf.derive(b"\x02" * 16)

    def test_derive(self):
        prk = binascii.unhexlify(
            b"52169af5c485dcc2321eb8d26d5efa21fb9b93c98e38412ee2484cf14f0d0d23"
        )

        okm = binascii.unhexlify(b"1c3bc9e7c4547c5191c0d478cccaed55")

        oinfo = binascii.unhexlify(
            b"a1b2c3d4e53728157e634612c12d6d5223e204aeea4341565369647bd184bcd2"
            b"46f72971f292badaa2fe4124612cba"
        )

        ckdf = ConcatKDFHash(hashes.SHA256(), 16, oinfo)

        assert ckdf.derive(prk) == okm

    def test_buffer_protocol(self):
        prk = binascii.unhexlify(
            b"52169af5c485dcc2321eb8d26d5efa21fb9b93c98e38412ee2484cf14f0d0d23"
        )

        okm = binascii.unhexlify(b"1c3bc9e7c4547c5191c0d478cccaed55")

        oinfo = binascii.unhexlify(
            b"a1b2c3d4e53728157e634612c12d6d5223e204aeea4341565369647bd184bcd2"
            b"46f72971f292badaa2fe4124612cba"
        )

        ckdf = ConcatKDFHash(hashes.SHA256(), 16, oinfo)

        assert ckdf.derive(bytearray(prk)) == okm

    def test_verify(self):
        prk = binascii.unhexlify(
            b"52169af5c485dcc2321eb8d26d5efa21fb9b93c98e38412ee2484cf14f0d0d23"
        )

        okm = binascii.unhexlify(b"1c3bc9e7c4547c5191c0d478cccaed55")

        oinfo = binascii.unhexlify(
            b"a1b2c3d4e53728157e634612c12d6d5223e204aeea4341565369647bd184bcd2"
            b"46f72971f292badaa2fe4124612cba"
        )

        ckdf = ConcatKDFHash(hashes.SHA256(), 16, oinfo)

        ckdf.verify(prk, okm)

    def test_invalid_verify(self):
        prk = binascii.unhexlify(
            b"52169af5c485dcc2321eb8d26d5efa21fb9b93c98e38412ee2484cf14f0d0d23"
        )

        oinfo = binascii.unhexlify(
            b"a1b2c3d4e53728157e634612c12d6d5223e204aeea4341565369647bd184bcd2"
            b"46f72971f292badaa2fe4124612cba"
        )

        ckdf = ConcatKDFHash(hashes.SHA256(), 16, oinfo)

        with pytest.raises(InvalidKey):
            ckdf.verify(prk, b"wrong key")

    def test_unicode_typeerror(self):
        with pytest.raises(TypeError):
            ConcatKDFHash(
                hashes.SHA256(), 16, otherinfo=typing.cast(typing.Any, "foo")
            )

        with pytest.raises(TypeError):
            ckdf = ConcatKDFHash(hashes.SHA256(), 16, otherinfo=None)

            ckdf.derive(typing.cast(typing.Any, "foo"))

        with pytest.raises(TypeError):
            ckdf = ConcatKDFHash(hashes.SHA256(), 16, otherinfo=None)

            ckdf.verify(typing.cast(typing.Any, "foo"), b"bar")

        with pytest.raises(TypeError):
            ckdf = ConcatKDFHash(hashes.SHA256(), 16, otherinfo=None)

            ckdf.verify(b"foo", typing.cast(typing.Any, "bar"))

    def test_derive_into(self):
        prk = binascii.unhexlify(
            b"52169af5c485dcc2321eb8d26d5efa21fb9b93c98e38412ee2484cf14f0d0d23"
        )
        oinfo = binascii.unhexlify(
            b"a1b2c3d4e53728157e634612c12d6d5223e204aeea4341565369647bd184bcd2"
            b"46f72971f292badaa2fe4124612cba"
        )
        ckdf = ConcatKDFHash(hashes.SHA256(), 16, oinfo)
        buf = bytearray(16)
        n = ckdf.derive_into(prk, buf)
        assert n == 16
        # Verify the output matches what derive would produce
        ckdf2 = ConcatKDFHash(hashes.SHA256(), 16, oinfo)
        expected = ckdf2.derive(prk)
        assert buf == expected

    @pytest.mark.parametrize(
        ("buflen", "outlen"), [(15, 16), (17, 16), (8, 16), (32, 16)]
    )
    def test_derive_into_buffer_incorrect_size(self, buflen, outlen):
        ckdf = ConcatKDFHash(hashes.SHA256(), outlen, None)
        buf = bytearray(buflen)
        with pytest.raises(ValueError, match="buffer must be"):
            ckdf.derive_into(b"key", buf)

    def test_derive_into_already_finalized(self):
        ckdf = ConcatKDFHash(hashes.SHA256(), 16, None)
        buf = bytearray(16)
        ckdf.derive_into(b"key", buf)
        with pytest.raises(AlreadyFinalized):
            ckdf.derive_into(b"key", buf)


class TestConcatKDFHMAC:
    def test_length_limit(self):
        big_length = hashes.SHA256().digest_size * (2**32 - 1) + 1
        error = OverflowError if sys.maxsize <= 2**31 else ValueError

        with pytest.raises(error):
            ConcatKDFHMAC(hashes.SHA256(), big_length, None, None)

    def test_already_finalized(self):
        ckdf = ConcatKDFHMAC(hashes.SHA256(), 16, None, None)

        ckdf.derive(b"\x01" * 16)

        with pytest.raises(AlreadyFinalized):
            ckdf.derive(b"\x02" * 16)

    def test_derive(self):
        prk = binascii.unhexlify(
            b"013951627c1dea63ea2d7702dd24e963eef5faac6b4af7e4"
            b"b831cde499dff1ce45f6179f741c728aa733583b02409208"
            b"8f0af7fce1d045edbc5790931e8d5ca79c73"
        )

        okm = binascii.unhexlify(
            b"64ce901db10d558661f10b6836a122a7605323ce2f39bf27eaaac8b34cf89f2f"
        )

        oinfo = binascii.unhexlify(
            b"a1b2c3d4e55e600be5f367e0e8a465f4bf2704db00c9325c"
            b"9fbd216d12b49160b2ae5157650f43415653696421e68e"
        )

        ckdf = ConcatKDFHMAC(hashes.SHA512(), 32, None, oinfo)

        assert ckdf.derive(prk) == okm

    def test_buffer_protocol(self):
        prk = binascii.unhexlify(
            b"013951627c1dea63ea2d7702dd24e963eef5faac6b4af7e4"
            b"b831cde499dff1ce45f6179f741c728aa733583b02409208"
            b"8f0af7fce1d045edbc5790931e8d5ca79c73"
        )

        okm = binascii.unhexlify(
            b"64ce901db10d558661f10b6836a122a7605323ce2f39bf27eaaac8b34cf89f2f"
        )

        oinfo = binascii.unhexlify(
            b"a1b2c3d4e55e600be5f367e0e8a465f4bf2704db00c9325c"
            b"9fbd216d12b49160b2ae5157650f43415653696421e68e"
        )

        ckdf = ConcatKDFHMAC(hashes.SHA512(), 32, None, oinfo)

        assert ckdf.derive(bytearray(prk)) == okm

    def test_derive_explicit_salt(self):
        prk = binascii.unhexlify(
            b"013951627c1dea63ea2d7702dd24e963eef5faac6b4af7e4"
            b"b831cde499dff1ce45f6179f741c728aa733583b02409208"
            b"8f0af7fce1d045edbc5790931e8d5ca79c73"
        )

        okm = binascii.unhexlify(
            b"64ce901db10d558661f10b6836a122a7605323ce2f39bf27eaaac8b34cf89f2f"
        )

        oinfo = binascii.unhexlify(
            b"a1b2c3d4e55e600be5f367e0e8a465f4bf2704db00c9325c"
            b"9fbd216d12b49160b2ae5157650f43415653696421e68e"
        )

        ckdf = ConcatKDFHMAC(hashes.SHA512(), 32, b"\x00" * 128, oinfo)

        assert ckdf.derive(prk) == okm

    def test_verify(self):
        prk = binascii.unhexlify(
            b"013951627c1dea63ea2d7702dd24e963eef5faac6b4af7e4"
            b"b831cde499dff1ce45f6179f741c728aa733583b02409208"
            b"8f0af7fce1d045edbc5790931e8d5ca79c73"
        )

        okm = binascii.unhexlify(
            b"64ce901db10d558661f10b6836a122a7605323ce2f39bf27eaaac8b34cf89f2f"
        )

        oinfo = binascii.unhexlify(
            b"a1b2c3d4e55e600be5f367e0e8a465f4bf2704db00c9325c"
            b"9fbd216d12b49160b2ae5157650f43415653696421e68e"
        )

        ckdf = ConcatKDFHMAC(hashes.SHA512(), 32, None, oinfo)

        ckdf.verify(prk, okm)

    def test_invalid_verify(self):
        prk = binascii.unhexlify(
            b"013951627c1dea63ea2d7702dd24e963eef5faac6b4af7e4"
            b"b831cde499dff1ce45f6179f741c728aa733583b02409208"
            b"8f0af7fce1d045edbc5790931e8d5ca79c73"
        )

        oinfo = binascii.unhexlify(
            b"a1b2c3d4e55e600be5f367e0e8a465f4bf2704db00c9325c"
            b"9fbd216d12b49160b2ae5157650f43415653696421e68e"
        )

        ckdf = ConcatKDFHMAC(hashes.SHA512(), 32, None, oinfo)

        with pytest.raises(InvalidKey):
            ckdf.verify(prk, b"wrong key")

    def test_unicode_typeerror(self):
        with pytest.raises(TypeError):
            ConcatKDFHMAC(
                hashes.SHA256(),
                16,
                salt=typing.cast(typing.Any, "foo"),
                otherinfo=None,
            )

        with pytest.raises(TypeError):
            ConcatKDFHMAC(
                hashes.SHA256(),
                16,
                salt=None,
                otherinfo=typing.cast(typing.Any, "foo"),
            )

        with pytest.raises(TypeError):
            ckdf = ConcatKDFHMAC(
                hashes.SHA256(), 16, salt=None, otherinfo=None
            )

            ckdf.derive(typing.cast(typing.Any, "foo"))

        with pytest.raises(TypeError):
            ckdf = ConcatKDFHMAC(
                hashes.SHA256(), 16, salt=None, otherinfo=None
            )

            ckdf.verify(typing.cast(typing.Any, "foo"), b"bar")

        with pytest.raises(TypeError):
            ckdf = ConcatKDFHMAC(
                hashes.SHA256(), 16, salt=None, otherinfo=None
            )

            ckdf.verify(b"foo", typing.cast(typing.Any, "bar"))

    def test_unsupported_hash_algorithm(self):
        # ConcatKDF requires a hash algorithm with an internal block size.
        with pytest.raises(TypeError):
            ConcatKDFHMAC(hashes.SHA3_256(), 16, salt=None, otherinfo=None)

    def test_derive_into(self):
        prk = binascii.unhexlify(
            b"013951627c1dea63ea2d7702dd24e963eef5faac6b4af7e4"
            b"b831cde499dff1ce45f6179f741c728aa733583b02409208"
            b"8f0af7fce1d045edbc5790931e8d5ca79c73"
        )
        oinfo = binascii.unhexlify(
            b"a1b2c3d4e55e600be5f367e0e8a465f4bf2704db00c9325c"
            b"9fbd216d12b49160b2ae5157650f43415653696421e68e"
        )
        ckdf = ConcatKDFHMAC(hashes.SHA512(), 32, None, oinfo)
        buf = bytearray(32)
        n = ckdf.derive_into(prk, buf)
        assert n == 32
        # Verify the output matches what derive would produce
        ckdf2 = ConcatKDFHMAC(hashes.SHA512(), 32, None, oinfo)
        expected = ckdf2.derive(prk)
        assert buf == expected

    @pytest.mark.parametrize(
        ("buflen", "outlen"), [(31, 32), (33, 32), (16, 32), (64, 32)]
    )
    def test_derive_into_buffer_incorrect_size(self, buflen, outlen):
        ckdf = ConcatKDFHMAC(hashes.SHA512(), outlen, None, None)
        buf = bytearray(buflen)
        with pytest.raises(ValueError, match="buffer must be"):
            ckdf.derive_into(b"key", buf)

    def test_derive_into_already_finalized(self):
        ckdf = ConcatKDFHMAC(hashes.SHA512(), 32, None, None)
        buf = bytearray(32)
        ckdf.derive_into(b"key", buf)
        with pytest.raises(AlreadyFinalized):
            ckdf.derive_into(b"key", buf)
