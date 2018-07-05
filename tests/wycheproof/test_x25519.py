# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)

from .utils import load_tests

def test_x25519(backend, wycheproof):
    for group, test in load_tests(wycheproof, "x25519_test.json"):
        assert not group
        private_key = X25519PrivateKey._from_private_bytes(
            binascii.unhexlify(test["private"])
        )
        public_key = X25519PublicKey.from_public_bytes(
            binascii.unhexlify(test["public"])
        )

        assert test["result"] in ["valid", "acceptable"]
        assert (
            private_key.exchange(public_key) ==
            binascii.unhexlify(test["shared"]
        )
