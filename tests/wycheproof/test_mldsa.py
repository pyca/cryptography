# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa65 import (
    MlDsa65PrivateKey,
    MlDsa65PublicKey,
)

from .utils import wycheproof_tests


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA-65 support",
)
@wycheproof_tests("mldsa_65_verify_test.json")
def test_mldsa65_verify(backend, wycheproof):
    try:
        pub = wycheproof.cache_value_to_group(
            "cached_pub",
            lambda: MlDsa65PublicKey.from_public_bytes(
                binascii.unhexlify(wycheproof.testgroup["publicKey"])
            ),
        )
    except ValueError:
        assert wycheproof.invalid
        assert wycheproof.has_flag("IncorrectPublicKeyLength")
        return

    msg = binascii.unhexlify(wycheproof.testcase["msg"])
    sig = binascii.unhexlify(wycheproof.testcase["sig"])
    has_ctx = "ctx" in wycheproof.testcase
    ctx = binascii.unhexlify(wycheproof.testcase["ctx"]) if has_ctx else None

    if wycheproof.valid:
        if has_ctx:
            pub.verify_with_context(sig, msg, ctx)
        else:
            pub.verify(sig, msg)
    else:
        with pytest.raises(
            (
                ValueError,
                InvalidSignature,
            )
        ):
            if has_ctx:
                pub.verify_with_context(sig, msg, ctx)
            else:
                pub.verify(sig, msg)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA-65 support",
)
@wycheproof_tests("mldsa_65_sign_seed_test.json")
def test_mldsa65_sign_seed(backend, wycheproof):
    # Skip "Internal" tests
    if wycheproof.has_flag("Internal"):
        return

    seed = wycheproof.cache_value_to_group(
        "cached_seed",
        lambda: binascii.unhexlify(wycheproof.testgroup["privateSeed"]),
    )
    key = wycheproof.cache_value_to_group(
        "cached_key",
        lambda: MlDsa65PrivateKey.from_seed_bytes(seed),
    )
    pub = wycheproof.cache_value_to_group(
        "cached_pub",
        lambda: MlDsa65PublicKey.from_public_bytes(
            binascii.unhexlify(wycheproof.testgroup["publicKey"])
        ),
    )

    assert key.public_key() == pub

    msg = binascii.unhexlify(wycheproof.testcase["msg"])
    has_ctx = "ctx" in wycheproof.testcase
    ctx = binascii.unhexlify(wycheproof.testcase["ctx"]) if has_ctx else None

    if wycheproof.valid or wycheproof.acceptable:
        # Sign and verify round-trip. We don't compare exact signature
        # bytes because some backends use hedged (randomized) signing.
        if has_ctx:
            sig = key.sign_with_context(msg, ctx)
            pub.verify_with_context(sig, msg, ctx)
        else:
            sig = key.sign(msg)
            pub.verify(sig, msg)
    else:
        with pytest.raises(ValueError):
            assert has_ctx
            key.sign_with_context(msg, ctx)
