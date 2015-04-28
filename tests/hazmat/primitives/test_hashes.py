# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pretend

import pytest

from cryptography import utils
from cryptography.exceptions import AlreadyFinalized, _Reasons
from cryptography.hazmat.backends.interfaces import HashBackend
from cryptography.hazmat.primitives import hashes

from .utils import generate_base_hash_test
from ..backends.test_multibackend import DummyHashBackend
from ...utils import raises_unsupported_algorithm


@utils.register_interface(hashes.HashAlgorithm)
class UnsupportedDummyHash(object):
    name = "unsupported-dummy-hash"
    block_size = None
    digest_size = None


@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestHashContext(object):
    def test_hash_reject_unicode(self, backend):
        m = hashes.Hash(hashes.SHA1(), backend=backend)
        with pytest.raises(TypeError):
            m.update(u"\u00FC")

    def test_copy_backend_object(self):
        backend = DummyHashBackend([hashes.SHA1])
        copied_ctx = pretend.stub()
        pretend_ctx = pretend.stub(copy=lambda: copied_ctx)
        h = hashes.Hash(hashes.SHA1(), backend=backend, ctx=pretend_ctx)
        assert h._backend is backend
        assert h.copy()._backend is h._backend

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
            hashes.Hash(UnsupportedDummyHash(), backend)


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.SHA1()),
    skip_message="Does not support SHA1",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestSHA1(object):
    test_SHA1 = generate_base_hash_test(
        hashes.SHA1(),
        digest_size=20,
        block_size=64,
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
        block_size=64,
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
        block_size=64,
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
        block_size=128,
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
        block_size=128,
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.RIPEMD160()),
    skip_message="Does not support RIPEMD160",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestRIPEMD160(object):
    test_RIPEMD160 = generate_base_hash_test(
        hashes.RIPEMD160(),
        digest_size=20,
        block_size=64,
    )


@pytest.mark.supported(
    only_if=lambda backend: backend.hash_supported(hashes.Whirlpool()),
    skip_message="Does not support Whirlpool",
)
@pytest.mark.requires_backend_interface(interface=HashBackend)
class TestWhirlpool(object):
    test_Whirlpool = generate_base_hash_test(
        hashes.Whirlpool(),
        digest_size=64,
        block_size=64,
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
        block_size=64,
    )


def test_invalid_backend():
    pretend_backend = object()

    with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
        hashes.Hash(hashes.SHA1(), pretend_backend)
