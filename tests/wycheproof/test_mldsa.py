# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii
import hashlib

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


def _compute_mu(pub_raw: bytes, msg: bytes, ctx: bytes) -> bytes:
    # FIPS 204: mu = SHAKE256(SHAKE256(pk, 64) || M', 64) where for pure
    # ML-DSA M' = 0x00 || len(ctx) || ctx || M.
    tr = hashlib.shake_256(pub_raw).digest(64)
    m_prime = b"\x00" + bytes([len(ctx)]) + ctx + msg
    return hashlib.shake_256(tr + m_prime).digest(64)


def _external_mu_test(public_key_class, wycheproof):
    # The sign vectors carry a precomputed mu ("External Mu") for every case
    # that has a valid signature, including the "Internal" cases that NIST
    # provides as bare mu values with no message or context. Those are
    # skipped by the signing tests above (we don't expose Sign_internal) but
    # exercise the precomputed-mu verification interface here.
    if "mu" not in wycheproof.testcase or not wycheproof.valid:
        return

    pub_raw = binascii.unhexlify(wycheproof.testgroup["publicKey"])
    pub = public_key_class.from_public_bytes(pub_raw)
    mu = binascii.unhexlify(wycheproof.testcase["mu"])
    sig = binascii.unhexlify(wycheproof.testcase["sig"])

    # The signature verifies through the precomputed-mu interface.
    pub.verify_mu(sig, mu)
    # And must not verify against a different mu.
    with pytest.raises(InvalidSignature):
        pub.verify_mu(bytes(sig), bytes([mu[0] ^ 0x01]) + mu[1:])

    # When the message (and optional context) are also provided, the mu we
    # derive must match the one in the vector, and the signature is an
    # ordinary ML-DSA signature over that message.
    if "msg" in wycheproof.testcase:
        msg = binascii.unhexlify(wycheproof.testcase["msg"])
        ctx = binascii.unhexlify(wycheproof.testcase.get("ctx", ""))
        assert _compute_mu(pub_raw, msg, ctx) == mu
        pub.verify(sig, msg, ctx)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA support",
)
@wycheproof_tests("mldsa_44_sign_seed_test.json")
def test_mldsa44_external_mu(backend, wycheproof):
    _external_mu_test(MLDSA44PublicKey, wycheproof)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA support",
)
@wycheproof_tests("mldsa_65_sign_seed_test.json")
def test_mldsa65_external_mu(backend, wycheproof):
    _external_mu_test(MLDSA65PublicKey, wycheproof)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA support",
)
@wycheproof_tests("mldsa_87_sign_seed_test.json")
def test_mldsa87_external_mu(backend, wycheproof):
    _external_mu_test(MLDSA87PublicKey, wycheproof)


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
