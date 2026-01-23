# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MlDsa44PrivateKey,
    MlDsa44PublicKey,
    MlDsa65PrivateKey,
    MlDsa65PublicKey,
)

from .utils import wycheproof_tests


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa44_supported(),
    skip_message="Requires OpenSSL with ML-DSA-44 support",
)
@wycheproof_tests("mldsa_44_sign_seed_test.json")
def test_mldsa44_signature(backend, wycheproof):
    if wycheproof.has_flag("Internal"):
        alg = getattr(wycheproof.testfiledata, "algorithm", None)
        pytest.skip(f"Internal implementation test for {alg}")

    assert wycheproof.testgroup["type"] == "MlDsaSign"

    seed = binascii.unhexlify(wycheproof.testgroup["privateSeed"])
    try:
        private_key = MlDsa44PrivateKey.from_seed_bytes(seed)
    except ValueError:
        assert wycheproof.invalid
        assert wycheproof.has_flag("IncorrectPrivateKeyLength")
        return
    try:
        public_key = MlDsa44PublicKey.from_public_bytes(
            binascii.unhexlify(wycheproof.testgroup["publicKey"])
        )
    except ValueError:
        assert wycheproof.invalid
        assert wycheproof.has_flag("IncorrectPublicKeyLength")
        return

    pkey_pkcs8 = wycheproof.testgroup.get("privateKeyPkcs8", None)
    if pkey_pkcs8 is not None:
        serialization.load_der_private_key(
            binascii.unhexlify(pkey_pkcs8), None
        )

    testkey = private_key.public_key()

    assert public_key.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ) == testkey.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )

    msg = binascii.unhexlify(wycheproof.testcase["msg"])
    expected_sig = binascii.unhexlify(wycheproof.testcase["sig"])
    context = wycheproof.testcase.get("ctx", None)
    if wycheproof.valid:
        if context is not None:
            context = binascii.unhexlify(context)
            testkey.verify_with_context(expected_sig, msg, context)
        else:
            public_key.verify(expected_sig, msg)
    else:
        with pytest.raises(InvalidSignature):
            if context is not None:
                context = binascii.unhexlify(context)
                testkey.verify_with_context(expected_sig, msg, context)
            else:
                public_key.verify(expected_sig, msg)


@pytest.mark.supported(
    only_if=lambda backend: backend.mldsa_supported(),
    skip_message="Requires a backend with ML-DSA-65 support",
)
@wycheproof_tests("mldsa_65_verify_test.json")
def test_mldsa65_verify(backend, wycheproof):
    try:
        pub = MlDsa65PublicKey.from_public_bytes(
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
    skip_message="Requires a backend with ML-DSA-65 support",
)
@wycheproof_tests("mldsa_65_sign_seed_test.json")
def test_mldsa65_sign_seed(backend, wycheproof):
    # Skip "Internal" tests, they use the inner method `Sign_internal`
    # instead of `Sign` which we do not expose.
    if wycheproof.has_flag("Internal"):
        return

    seed = binascii.unhexlify(wycheproof.testgroup["privateSeed"])
    try:
        key = MlDsa65PrivateKey.from_seed_bytes(seed)
    except ValueError:
        assert wycheproof.invalid
        assert wycheproof.has_flag("IncorrectPrivateKeyLength")
        return
    pub = MlDsa65PublicKey.from_public_bytes(
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
