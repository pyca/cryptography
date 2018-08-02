# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends.interfaces import RSABackend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


_DIGESTS = {
    "SHA-1": hashes.SHA1(),
    "SHA-224": hashes.SHA224(),
    "SHA-256": hashes.SHA256(),
    "SHA-384": hashes.SHA384(),
    "SHA-512": hashes.SHA512(),
}


def should_verify(backend, wycheproof):
    if wycheproof.valid:
        return True

    if wycheproof.acceptable:
        if (
            backend._lib.CRYPTOGRAPHY_OPENSSL_110_OR_GREATER and
            wycheproof.has_flag("MissingNull")
        ):
            return False
        return True

    return False


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.supported(
    only_if=lambda backend: (
        # TODO: this also skips on LibreSSL, which is ok for now, since these
        # don't pass on Libre, but we'll need to fix this when LibreSSL 2.8 is
        # released.
        not backend._lib.CRYPTOGRAPHY_OPENSSL_LESS_THAN_102
    ),
    skip_message=(
        "Many of these tests fail on OpenSSL < 1.0.2 and since upstream isn't"
        " maintaining it, they'll never be fixed."
    ),
)
@pytest.mark.wycheproof_tests(
    "rsa_signature_test.json",
    "rsa_signature_2048_sha224_test.json",
    "rsa_signature_2048_sha256_test.json",
    "rsa_signature_2048_sha512_test.json",
    "rsa_signature_3072_sha256_test.json",
    "rsa_signature_3072_sha384_test.json",
    "rsa_signature_3072_sha512_test.json",
    "rsa_signature_4096_sha384_test.json",
    "rsa_signature_4096_sha512_test.json",
)
def test_rsa_pkcs1v15_signature(backend, wycheproof):
    key = serialization.load_der_public_key(
        binascii.unhexlify(wycheproof.testgroup["keyDer"]), backend
    )
    digest = _DIGESTS[wycheproof.testgroup["sha"]]

    if should_verify(backend, wycheproof):
        key.verify(
            binascii.unhexlify(wycheproof.testcase["sig"]),
            binascii.unhexlify(wycheproof.testcase["msg"]),
            padding.PKCS1v15(),
            digest,
        )
    else:
        with pytest.raises(InvalidSignature):
            key.verify(
                binascii.unhexlify(wycheproof.testcase["sig"]),
                binascii.unhexlify(wycheproof.testcase["msg"]),
                padding.PKCS1v15(),
                digest,
            )


@pytest.mark.requires_backend_interface(interface=RSABackend)
@pytest.mark.wycheproof_tests(
    "rsa_pss_2048_sha1_mgf1_20_test.json",
    "rsa_pss_2048_sha256_mgf1_0_test.json",
    "rsa_pss_2048_sha256_mgf1_32_test.json",
    "rsa_pss_3072_sha256_mgf1_32_test.json",
    "rsa_pss_4096_sha256_mgf1_32_test.json",
    "rsa_pss_4096_sha512_mgf1_32_test.json",
    "rsa_pss_misc_test.json",
)
def test_rsa_pss_signature(backend, wycheproof):
    key = serialization.load_der_public_key(
        binascii.unhexlify(wycheproof.testgroup["keyDer"]), backend
    )
    digest = _DIGESTS[wycheproof.testgroup["sha"]]
    mgf_digest = _DIGESTS[wycheproof.testgroup["mgfSha"]]

    if wycheproof.valid or wycheproof.acceptable:
        key.verify(
            binascii.unhexlify(wycheproof.testcase["sig"]),
            binascii.unhexlify(wycheproof.testcase["msg"]),
            padding.PSS(
                mgf=padding.MGF1(mgf_digest),
                salt_length=wycheproof.testgroup["sLen"]
            ),
            digest
        )
    else:
        with pytest.raises(InvalidSignature):
            key.verify(
                binascii.unhexlify(wycheproof.testcase["sig"]),
                binascii.unhexlify(wycheproof.testcase["msg"]),
                padding.PSS(
                    mgf=padding.MGF1(mgf_digest),
                    salt_length=wycheproof.testgroup["sLen"]
                ),
                digest
            )
