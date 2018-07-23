# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.exceptions import AlreadyFinalized, _Reasons
from cryptography.hazmat.backends.interfaces import HashBackend
from cryptography.hazmat.primitives import hashes

from .utils import generate_base_hash_test
from ...doubles import DummyHashAlgorithm
from ...utils import raises_unsupported_algorithm


@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestHashContext(object):
    def test_hash_reject_unicode(self, backend):
        m = hashes.Hash(hashes.SHA1(), backend=backend)
        with pytest.raises(TypeError):
            m.update(u"\u00FC")

    def test_hash_algorithm_instance(self, backend):
        with pytest.raises(TypeError):
            hashes.Hash(hashes.SHA1, backend=backend)

    def test_raises_after_finalize(self, backend):
        h = hashes.Hash(hashes.SHA1(), backend=backend)
        h.finalize()

        with pytest.raises(AlreadyFinalized):
            h.update(b"foo")

        with pytest.raises(AlreadyFinalized):
            h.copy()

        with pytest.raises(AlreadyFinalized):
            h.finalize()

    def test_unsupported_hash(self, backend):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            hashes.Hash(DummyHashAlgorithm(), backend)


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.SHA1()),
    skip_message="Does not support SHA1",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestSHA1(object):
    test_SHA1 = generate_base_hash_test(
        hashes.SHA1(),
        digest_size=20,
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.SHA224()),
    skip_message="Does not support SHA224",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestSHA224(object):
    test_SHA224 = generate_base_hash_test(
        hashes.SHA224(),
        digest_size=28,
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.SHA256()),
    skip_message="Does not support SHA256",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestSHA256(object):
    test_SHA256 = generate_base_hash_test(
        hashes.SHA256(),
        digest_size=32,
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.SHA384()),
    skip_message="Does not support SHA384",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestSHA384(object):
    test_SHA384 = generate_base_hash_test(
        hashes.SHA384(),
        digest_size=48,
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.SHA512()),
    skip_message="Does not support SHA512",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestSHA512(object):
    test_SHA512 = generate_base_hash_test(
        hashes.SHA512(),
        digest_size=64,
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.MD5()),
    skip_message="Does not support MD5",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestMD5(object):
    test_MD5 = generate_base_hash_test(
        hashes.MD5(),
        digest_size=16,
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(
        hashes.BLAKE2b(digest_size=64)),
    skip_message="Does not support BLAKE2b",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestBLAKE2b(object):
    test_BLAKE2b = generate_base_hash_test(
        hashes.BLAKE2b(digest_size=64),
        digest_size=64,
    )

    def test_invalid_digest_size(self, backend):
        with pytest.raises(ValueError):
            hashes.BLAKE2b(digest_size=65)

        with pytest.raises(ValueError):
            hashes.BLAKE2b(digest_size=0)

        with pytest.raises(ValueError):
            hashes.BLAKE2b(digest_size=-1)


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(
        hashes.BLAKE2s(digest_size=32)),
    skip_message="Does not support BLAKE2s",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestBLAKE2s(object):
    test_BLAKE2s = generate_base_hash_test(
        hashes.BLAKE2s(digest_size=32),
        digest_size=32,
    )

    def test_invalid_digest_size(self, backend):
        with pytest.raises(ValueError):
            hashes.BLAKE2s(digest_size=33)

        with pytest.raises(ValueError):
            hashes.BLAKE2s(digest_size=0)

        with pytest.raises(ValueError):
            hashes.BLAKE2s(digest_size=-1)


def test_invalid_backend():
    pretend_backend = object()

    with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
        hashes.Hash(hashes.SHA1(), pretend_backend)
