# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

import pytest

from cryptography.hazmat.backends.interfaces import HMACBackend
from cryptography.hazmat.primitives import hashes

from .utils import generate_hkdf_test
from ...utils import load_nist_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.SHA1()),
    skip_message="Does not support SHA1."
)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHKDFSHA1(object):
    test_HKDFSHA1 = generate_hkdf_test(
        load_nist_vectors,
        os.path.join("KDF"),
        ["rfc-5869-HKDF-SHA1.txt"],
        hashes.SHA1()
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.SHA256()),
    skip_message="Does not support SHA256."
)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHKDFSHA256(object):
    test_HKDFSHA1 = generate_hkdf_test(
        load_nist_vectors,
        os.path.join("KDF"),
        ["rfc-5869-HKDF-SHA256.txt"],
        hashes.SHA256()
    )
