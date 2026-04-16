# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import binascii

import pytest

from cryptography.hazmat.primitives.asymmetric.mlkem import (
    MLKEM512PrivateKey,
    MLKEM512PublicKey,
    MLKEM768PrivateKey,
    MLKEM768PublicKey,
    MLKEM1024PrivateKey,
    MLKEM1024PublicKey,
)

from .utils import wycheproof_tests


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-512 support",
)
@wycheproof_tests("mlkem_512_test.json")
def test_mlkem512_decaps(backend, wycheproof):
    seed = binascii.unhexlify(wycheproof.testcase["seed"])
    try:
        key = MLKEM512PrivateKey.from_seed_bytes(seed)
    except ValueError:
        assert wycheproof.invalid
        return

    ct = binascii.unhexlify(wycheproof.testcase["c"])
    expected_ss = binascii.unhexlify(wycheproof.testcase["K"])

    try:
        shared_secret = key.decapsulate(ct)
    except Exception as e:
        assert wycheproof.invalid, f"Unexpected error on valid test: {e}"
        return

    assert shared_secret == expected_ss


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-512 support",
)
@wycheproof_tests("mlkem_512_keygen_seed_test.json")
def test_mlkem512_keygen_seed(backend, wycheproof):
    seed = binascii.unhexlify(wycheproof.testcase["seed"])
    expected_ek = binascii.unhexlify(wycheproof.testcase["ek"])

    key = MLKEM512PrivateKey.from_seed_bytes(seed)

    pub = key.public_key()
    assert pub.public_bytes_raw() == expected_ek


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-512 support",
)
@wycheproof_tests("mlkem_512_encaps_test.json")
def test_mlkem512_encaps(backend, wycheproof):
    ek = binascii.unhexlify(wycheproof.testcase["ek"])

    try:
        pub = MLKEM512PublicKey.from_public_bytes(ek)
    except ValueError:
        assert wycheproof.invalid
        return

    # We can't test deterministic encapsulation (no API to pass
    # the random seed m), so verify the key loads and encapsulate
    # produces correctly sized output.
    try:
        shared_secret, ciphertext = pub.encapsulate()
    except ValueError:
        assert wycheproof.invalid
        return

    assert wycheproof.valid
    assert len(shared_secret) == 32
    assert len(ciphertext) == 768


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
@wycheproof_tests("mlkem_768_test.json")
def test_mlkem768_decaps(backend, wycheproof):
    seed = binascii.unhexlify(wycheproof.testcase["seed"])
    try:
        key = MLKEM768PrivateKey.from_seed_bytes(seed)
    except ValueError:
        assert wycheproof.invalid
        return

    ct = binascii.unhexlify(wycheproof.testcase["c"])
    expected_ss = binascii.unhexlify(wycheproof.testcase["K"])

    try:
        shared_secret = key.decapsulate(ct)
    except Exception as e:
        assert wycheproof.invalid, f"Unexpected error on valid test: {e}"
        return

    assert shared_secret == expected_ss


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
@wycheproof_tests("mlkem_768_keygen_seed_test.json")
def test_mlkem768_keygen_seed(backend, wycheproof):
    seed = binascii.unhexlify(wycheproof.testcase["seed"])
    expected_ek = binascii.unhexlify(wycheproof.testcase["ek"])

    key = MLKEM768PrivateKey.from_seed_bytes(seed)

    pub = key.public_key()
    assert pub.public_bytes_raw() == expected_ek


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-768 support",
)
@wycheproof_tests("mlkem_768_encaps_test.json")
def test_mlkem768_encaps(backend, wycheproof):
    ek = binascii.unhexlify(wycheproof.testcase["ek"])

    try:
        pub = MLKEM768PublicKey.from_public_bytes(ek)
    except ValueError:
        assert wycheproof.invalid
        return

    # We can't test deterministic encapsulation (no API to pass
    # the random seed m), so verify the key loads and encapsulate
    # produces correctly sized output.
    try:
        shared_secret, ciphertext = pub.encapsulate()
    except ValueError:
        assert wycheproof.invalid
        return

    assert wycheproof.valid
    assert len(shared_secret) == 32
    assert len(ciphertext) == 1088


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-1024 support",
)
@wycheproof_tests("mlkem_1024_test.json")
def test_mlkem1024_decaps(backend, wycheproof):
    seed = binascii.unhexlify(wycheproof.testcase["seed"])
    try:
        key = MLKEM1024PrivateKey.from_seed_bytes(seed)
    except ValueError:
        assert wycheproof.invalid
        return

    ct = binascii.unhexlify(wycheproof.testcase["c"])
    expected_ss = binascii.unhexlify(wycheproof.testcase["K"])

    try:
        shared_secret = key.decapsulate(ct)
    except Exception as e:
        assert wycheproof.invalid, f"Unexpected error on valid test: {e}"
        return

    assert shared_secret == expected_ss


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-1024 support",
)
@wycheproof_tests("mlkem_1024_keygen_seed_test.json")
def test_mlkem1024_keygen_seed(backend, wycheproof):
    seed = binascii.unhexlify(wycheproof.testcase["seed"])
    expected_ek = binascii.unhexlify(wycheproof.testcase["ek"])

    key = MLKEM1024PrivateKey.from_seed_bytes(seed)

    pub = key.public_key()
    assert pub.public_bytes_raw() == expected_ek


@pytest.mark.supported(
    only_if=lambda backend: backend.mlkem_supported(),
    skip_message="Requires a backend with ML-KEM-1024 support",
)
@wycheproof_tests("mlkem_1024_encaps_test.json")
def test_mlkem1024_encaps(backend, wycheproof):
    ek = binascii.unhexlify(wycheproof.testcase["ek"])

    try:
        pub = MLKEM1024PublicKey.from_public_bytes(ek)
    except ValueError:
        assert wycheproof.invalid
        return

    # We can't test deterministic encapsulation (no API to pass
    # the random seed m), so verify the key loads and encapsulate
    # produces correctly sized output.
    try:
        shared_secret, ciphertext = pub.encapsulate()
    except ValueError:
        assert wycheproof.invalid
        return

    assert wycheproof.valid
    assert len(shared_secret) == 32
    assert len(ciphertext) == 1568
