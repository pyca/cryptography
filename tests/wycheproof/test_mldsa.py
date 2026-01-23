# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.mldsa44 import (
    MlDsa44PrivateKey,
    MlDsa44PublicKey,
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

    private_key = MlDsa44PrivateKey.from_seed_bytes(
        binascii.unhexlify(wycheproof.testgroup["privateSeed"])
    )
    public_key = MlDsa44PublicKey.from_public_bytes(
        binascii.unhexlify(wycheproof.testgroup["publicKey"])
    )

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
