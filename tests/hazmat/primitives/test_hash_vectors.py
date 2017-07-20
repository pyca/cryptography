# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import os

import pytest

from cryptography.hazmat.backends.interfaces import HashBackend
from cryptography.hazmat.primitives import hashes

from .utils import generate_hash_test
from ...utils import load_hash_vectors


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.SHA1()),
    skip_message="Does not support SHA1",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestSHA1(object):
    test_SHA1 = generate_hash_test(
        load_hash_vectors,
        os.path.join("hashes", "SHA1"),
        [
            "SHA1LongMsg.rsp",
            "SHA1ShortMsg.rsp",
        ],
        hashes.SHA1(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.SHA224()),
    skip_message="Does not support SHA224",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestSHA224(object):
    test_SHA224 = generate_hash_test(
        load_hash_vectors,
        os.path.join("hashes", "SHA2"),
        [
            "SHA224LongMsg.rsp",
            "SHA224ShortMsg.rsp",
        ],
        hashes.SHA224(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.SHA256()),
    skip_message="Does not support SHA256",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestSHA256(object):
    test_SHA256 = generate_hash_test(
        load_hash_vectors,
        os.path.join("hashes", "SHA2"),
        [
            "SHA256LongMsg.rsp",
            "SHA256ShortMsg.rsp",
        ],
        hashes.SHA256(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.SHA384()),
    skip_message="Does not support SHA384",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestSHA384(object):
    test_SHA384 = generate_hash_test(
        load_hash_vectors,
        os.path.join("hashes", "SHA2"),
        [
            "SHA384LongMsg.rsp",
            "SHA384ShortMsg.rsp",
        ],
        hashes.SHA384(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.SHA512()),
    skip_message="Does not support SHA512",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestSHA512(object):
    test_SHA512 = generate_hash_test(
        load_hash_vectors,
        os.path.join("hashes", "SHA2"),
        [
            "SHA512LongMsg.rsp",
            "SHA512ShortMsg.rsp",
        ],
        hashes.SHA512(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.MD5()),
    skip_message="Does not support MD5",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestMD5(object):
    test_md5 = generate_hash_test(
        load_hash_vectors,
        os.path.join("hashes", "MD5"),
        [
            "rfc-1321.txt",
        ],
        hashes.MD5(),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(
        hashes.BLAKE2b(digest_size=64)),
    skip_message="Does not support BLAKE2b",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestBLAKE2b(object):
    test_b2b = generate_hash_test(
        load_hash_vectors,
        os.path.join("hashes", "blake2"),
        [
            "blake2b.txt",
        ],
        hashes.BLAKE2b(digest_size=64),
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(
        hashes.BLAKE2s(digest_size=32)),
    skip_message="Does not support BLAKE2s",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestBLAKE2s256(object):
    test_b2s = generate_hash_test(
        load_hash_vectors,
        os.path.join("hashes", "blake2"),
        [
            "blake2s.txt",
        ],
        hashes.BLAKE2s(digest_size=32),
    )
