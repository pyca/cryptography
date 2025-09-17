# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii

import pytest

from cryptography.hazmat.primitives import keywrap

from .utils import wycheproof_tests


@wycheproof_tests("aes_kwp_test.json")
def test_keywrap_with_padding(backend, wycheproof):
    wrapping_key = binascii.unhexlify(wycheproof.testcase["key"])
    key_to_wrap = binascii.unhexlify(wycheproof.testcase["msg"])
    expected = binascii.unhexlify(wycheproof.testcase["ct"])

    result = keywrap.aes_key_wrap_with_padding(
        wrapping_key, key_to_wrap, backend
    )
    if wycheproof.valid or wycheproof.acceptable:
        assert result == expected

    if wycheproof.valid or (wycheproof.acceptable and not len(expected) < 16):
        result = keywrap.aes_key_unwrap_with_padding(
            wrapping_key, expected, backend
        )
        assert result == key_to_wrap
    else:
        with pytest.raises(keywrap.InvalidUnwrap):
            keywrap.aes_key_unwrap_with_padding(
                wrapping_key, expected, backend
            )


@wycheproof_tests("aes_wrap_test.json")
def test_keywrap(backend, wycheproof):
    wrapping_key = binascii.unhexlify(wycheproof.testcase["key"])
    key_to_wrap = binascii.unhexlify(wycheproof.testcase["msg"])
    expected = binascii.unhexlify(wycheproof.testcase["ct"])

    if wycheproof.invalid or (
        wycheproof.acceptable and wycheproof.has_flag("ShortKey")
    ):
        if not wycheproof.has_flag(
            "InvalidWrappingSize"
        ) and not wycheproof.has_flag("ModifiedIv"):
            with pytest.raises(ValueError):
                keywrap.aes_key_wrap(wrapping_key, key_to_wrap, backend)

        with pytest.raises(keywrap.InvalidUnwrap):
            keywrap.aes_key_unwrap(wrapping_key, expected, backend)
    else:
        result = keywrap.aes_key_wrap(wrapping_key, key_to_wrap, backend)
        assert result == expected

        result = keywrap.aes_key_unwrap(wrapping_key, expected, backend)
        assert result == key_to_wrap
