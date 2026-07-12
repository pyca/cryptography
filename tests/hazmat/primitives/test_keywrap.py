# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import binascii
import os

import pytest

from cryptography.hazmat.primitives import keywrap

from ...utils import load_nist_vectors
from .utils import _load_all_params


class TestAESKeyWrap:
    def test_wrap(self, subtests):
        params = _load_all_params(
            os.path.join("keywrap", "kwtestvectors"),
            ["KW_AE_128.txt", "KW_AE_192.txt", "KW_AE_256.txt"],
            load_nist_vectors,
        )
        for param in params:
            with subtests.test():
                wrapping_key = binascii.unhexlify(param["k"])
                key_to_wrap = binascii.unhexlify(param["p"])
                wrapped_key = keywrap.aes_key_wrap(wrapping_key, key_to_wrap)
                assert param["c"] == binascii.hexlify(wrapped_key)

    def test_unwrap(self, subtests):
        params = _load_all_params(
            os.path.join("keywrap", "kwtestvectors"),
            ["KW_AD_128.txt", "KW_AD_192.txt", "KW_AD_256.txt"],
            load_nist_vectors,
        )
        for param in params:
            with subtests.test():
                wrapping_key = binascii.unhexlify(param["k"])
                wrapped_key = binascii.unhexlify(param["c"])
                if param.get("fail") is True:
                    with pytest.raises(keywrap.InvalidUnwrap):
                        keywrap.aes_key_unwrap(wrapping_key, wrapped_key)
                else:
                    unwrapped_key = keywrap.aes_key_unwrap(
                        wrapping_key, wrapped_key
                    )
                    assert param["p"] == binascii.hexlify(unwrapped_key)

    def test_wrap_invalid_key_length(self):
        # The wrapping key must be of length [16, 24, 32]
        with pytest.raises(ValueError):
            keywrap.aes_key_wrap(b"badkey", b"sixteen_byte_key")

    def test_unwrap_invalid_key_length(self):
        with pytest.raises(ValueError):
            keywrap.aes_key_unwrap(b"badkey", b"\x00" * 24)

    def test_wrap_invalid_key_to_wrap_length(self):
        # Keys to wrap must be at least 16 bytes long
        with pytest.raises(ValueError):
            keywrap.aes_key_wrap(b"sixteen_byte_key", b"\x00" * 15)

        # Keys to wrap must be a multiple of 8 bytes
        with pytest.raises(ValueError):
            keywrap.aes_key_wrap(b"sixteen_byte_key", b"\x00" * 23)

    def test_unwrap_invalid_wrapped_key_length(self):
        # Keys to unwrap must be at least 24 bytes
        with pytest.raises(keywrap.InvalidUnwrap):
            keywrap.aes_key_unwrap(b"sixteen_byte_key", b"\x00" * 16)

        # Keys to unwrap must be a multiple of 8 bytes
        with pytest.raises(keywrap.InvalidUnwrap):
            keywrap.aes_key_unwrap(b"sixteen_byte_key", b"\x00" * 27)

    def test_wrap_unwrap_large_roundtrip(self):
        wrapping_key = os.urandom(32)
        key_to_wrap = os.urandom(4096)
        wrapped = keywrap.aes_key_wrap(wrapping_key, key_to_wrap)
        assert keywrap.aes_key_unwrap(wrapping_key, wrapped) == key_to_wrap


class TestAESKeyWrapWithPadding:
    def test_wrap(self, subtests):
        params = _load_all_params(
            os.path.join("keywrap", "kwtestvectors"),
            ["KWP_AE_128.txt", "KWP_AE_192.txt", "KWP_AE_256.txt"],
            load_nist_vectors,
        )
        for param in params:
            with subtests.test():
                wrapping_key = binascii.unhexlify(param["k"])
                key_to_wrap = binascii.unhexlify(param["p"])
                wrapped_key = keywrap.aes_key_wrap_with_padding(
                    wrapping_key, key_to_wrap
                )
                assert param["c"] == binascii.hexlify(wrapped_key)

    def test_wrap_additional_vectors(self, subtests):
        params = _load_all_params(
            "keywrap", ["kwp_botan.txt"], load_nist_vectors
        )
        for param in params:
            with subtests.test():
                wrapping_key = binascii.unhexlify(param["key"])
                key_to_wrap = binascii.unhexlify(param["input"])
                wrapped_key = keywrap.aes_key_wrap_with_padding(
                    wrapping_key, key_to_wrap
                )
                assert wrapped_key == binascii.unhexlify(param["output"])

    def test_unwrap(self, subtests):
        params = _load_all_params(
            os.path.join("keywrap", "kwtestvectors"),
            ["KWP_AD_128.txt", "KWP_AD_192.txt", "KWP_AD_256.txt"],
            load_nist_vectors,
        )
        for param in params:
            with subtests.test():
                wrapping_key = binascii.unhexlify(param["k"])
                wrapped_key = binascii.unhexlify(param["c"])
                if param.get("fail") is True:
                    with pytest.raises(keywrap.InvalidUnwrap):
                        keywrap.aes_key_unwrap_with_padding(
                            wrapping_key, wrapped_key
                        )
                else:
                    unwrapped_key = keywrap.aes_key_unwrap_with_padding(
                        wrapping_key, wrapped_key
                    )
                    assert param["p"] == binascii.hexlify(unwrapped_key)

    def test_unwrap_additional_vectors(self, subtests):
        params = _load_all_params(
            "keywrap", ["kwp_botan.txt"], load_nist_vectors
        )
        for param in params:
            with subtests.test():
                wrapping_key = binascii.unhexlify(param["key"])
                wrapped_key = binascii.unhexlify(param["output"])
                unwrapped_key = keywrap.aes_key_unwrap_with_padding(
                    wrapping_key, wrapped_key
                )
                assert unwrapped_key == binascii.unhexlify(param["input"])

    def test_unwrap_invalid_wrapped_key_length(self):
        # Keys to unwrap must be at least 16 bytes
        with pytest.raises(
            keywrap.InvalidUnwrap, match="Must be at least 16 bytes"
        ):
            keywrap.aes_key_unwrap_with_padding(
                b"sixteen_byte_key", b"\x00" * 15
            )

        # Keys to unwrap must be a multiple of 8 bytes
        with pytest.raises(keywrap.InvalidUnwrap, match="multiple of 8 bytes"):
            keywrap.aes_key_unwrap_with_padding(
                b"sixteen_byte_key", b"\x00" * 17
            )

    def test_wrap_unwrap_large_roundtrip(self):
        wrapping_key = os.urandom(32)
        # Deliberately not a multiple of 8, to exercise padding.
        key_to_wrap = os.urandom(4099)
        wrapped = keywrap.aes_key_wrap_with_padding(wrapping_key, key_to_wrap)
        assert (
            keywrap.aes_key_unwrap_with_padding(wrapping_key, wrapped)
            == key_to_wrap
        )

    def test_wrap_empty_key_to_wrap(self):
        with pytest.raises(
            ValueError, match="key_to_wrap must be between 1 and 2\\^32 bytes"
        ):
            keywrap.aes_key_wrap_with_padding(b"\x00" * 16, b"")

    def test_wrap_invalid_key_length(self):
        with pytest.raises(ValueError, match="must be a valid AES key length"):
            keywrap.aes_key_wrap_with_padding(b"badkey", b"\x00")

    def test_unwrap_invalid_key_length(self):
        with pytest.raises(ValueError, match="must be a valid AES key length"):
            keywrap.aes_key_unwrap_with_padding(b"badkey", b"\x00" * 16)
