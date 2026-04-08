# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA44PrivateKey,
    MLDSA44PublicKey,
    MLDSA65PrivateKey,
    MLDSA65PublicKey,
    MLDSA87PrivateKey,
    MLDSA87PublicKey,
)

from .utils import wycheproof_tests


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA support",
)
@wycheproof_tests("mldsa_44_verify_test.json")
def test_mldsa44_verify(backend, wycheproof):
    try:
        pub = MLDSA44PublicKey.from_public_bytes(
            binascii.unhexlify(wycheproof.testgroup["publicKey"])
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
        pub.verify(sig, msg, ctx)
    else:
        with pytest.raises(
            (
                ValueError,
                InvalidSignature,
            )
        ):
            pub.verify(sig, msg, ctx)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA support",
)
@wycheproof_tests("mldsa_44_sign_seed_test.json")
def test_mldsa44_sign_seed(backend, wycheproof):
    # Skip "Internal" tests, they use the inner method `Sign_internal`
    # instead of `Sign` which we do not expose.
    if wycheproof.has_flag("Internal"):
        return

    seed = binascii.unhexlify(wycheproof.testgroup["privateSeed"])
    try:
        key = MLDSA44PrivateKey.from_seed_bytes(seed)
    except ValueError:
        assert wycheproof.invalid
        assert wycheproof.has_flag("IncorrectPrivateKeyLength")
        return
    pub = MLDSA44PublicKey.from_public_bytes(
        binascii.unhexlify(wycheproof.testgroup["publicKey"])
    )

    assert key.public_key() == pub

    msg = binascii.unhexlify(wycheproof.testcase["msg"])
    has_ctx = "ctx" in wycheproof.testcase
    ctx = binascii.unhexlify(wycheproof.testcase["ctx"]) if has_ctx else None

    if wycheproof.valid or wycheproof.acceptable:
        # Sign and verify round-trip. We don't compare exact signature
        # bytes because some backends use hedged (randomized) signing.
        sig = key.sign(msg, ctx)
        pub.verify(sig, msg, ctx)
    else:
        with pytest.raises(ValueError):
            assert has_ctx
            key.sign(msg, ctx)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA support",
)
@wycheproof_tests("mldsa_65_verify_test.json")
def test_mldsa65_verify(backend, wycheproof):
    try:
        pub = MLDSA65PublicKey.from_public_bytes(
            binascii.unhexlify(wycheproof.testgroup["publicKey"])
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
        pub.verify(sig, msg, ctx)
    else:
        with pytest.raises(
            (
                ValueError,
                InvalidSignature,
            )
        ):
            pub.verify(sig, msg, ctx)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA support",
)
@wycheproof_tests("mldsa_65_sign_seed_test.json")
def test_mldsa65_sign_seed(backend, wycheproof):
    # Skip "Internal" tests, they use the inner method `Sign_internal`
    # instead of `Sign` which we do not expose.
    if wycheproof.has_flag("Internal"):
        return

    seed = binascii.unhexlify(wycheproof.testgroup["privateSeed"])
    try:
        key = MLDSA65PrivateKey.from_seed_bytes(seed)
    except ValueError:
        assert wycheproof.invalid
        assert wycheproof.has_flag("IncorrectPrivateKeyLength")
        return
    pub = MLDSA65PublicKey.from_public_bytes(
        binascii.unhexlify(wycheproof.testgroup["publicKey"])
    )

    assert key.public_key() == pub

    msg = binascii.unhexlify(wycheproof.testcase["msg"])
    has_ctx = "ctx" in wycheproof.testcase
    ctx = binascii.unhexlify(wycheproof.testcase["ctx"]) if has_ctx else None

    if wycheproof.valid or wycheproof.acceptable:
        # Sign and verify round-trip. We don't compare exact signature
        # bytes because some backends use hedged (randomized) signing.
        sig = key.sign(msg, ctx)
        pub.verify(sig, msg, ctx)
    else:
        with pytest.raises(ValueError):
            assert has_ctx
            key.sign(msg, ctx)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA support",
)
@wycheproof_tests("mldsa_87_verify_test.json")
def test_mldsa87_verify(backend, wycheproof):
    try:
        pub = MLDSA87PublicKey.from_public_bytes(
            binascii.unhexlify(wycheproof.testgroup["publicKey"])
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
        pub.verify(sig, msg, ctx)
    else:
        with pytest.raises(
            (
                ValueError,
                InvalidSignature,
            )
        ):
            pub.verify(sig, msg, ctx)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA support",
)
@wycheproof_tests("mldsa_87_sign_seed_test.json")
def test_mldsa87_sign_seed(backend, wycheproof):
    # Skip "Internal" tests, they use the inner method `Sign_internal`
    # instead of `Sign` which we do not expose.
    if wycheproof.has_flag("Internal"):
        return

    seed = binascii.unhexlify(wycheproof.testgroup["privateSeed"])
    try:
        key = MLDSA87PrivateKey.from_seed_bytes(seed)
    except ValueError:
        assert wycheproof.invalid
        assert wycheproof.has_flag("IncorrectPrivateKeyLength")
        return
    pub = MLDSA87PublicKey.from_public_bytes(
        binascii.unhexlify(wycheproof.testgroup["publicKey"])
    )

    assert key.public_key() == pub

    msg = binascii.unhexlify(wycheproof.testcase["msg"])
    has_ctx = "ctx" in wycheproof.testcase
    ctx = binascii.unhexlify(wycheproof.testcase["ctx"]) if has_ctx else None

    if wycheproof.valid or wycheproof.acceptable:
        # Sign and verify round-trip. We don't compare exact signature
        # bytes because some backends use hedged (randomized) signing.
        sig = key.sign(msg, ctx)
        pub.verify(sig, msg, ctx)
    else:
        with pytest.raises(ValueError):
            assert has_ctx
            key.sign(msg, ctx)
