# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import pytest

from cryptography.exceptions import (
    AlreadyFinalized, InvalidSignature, _Reasons
)
from cryptography.hazmat.backends.interfaces import HMACBackend
from cryptography.hazmat.primitives import hashes, hmac

from .utils import generate_base_hmac_test
from ...doubles import DummyHashAlgorithm
from ...utils import raises_unsupported_algorithm


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.MD5()),
    skip_message="Does not support MD5",
)
@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHMACCopy(object):
    test_copy = generate_base_hmac_test(
        hashes.MD5(),
    )


@pytest.mark.requires_backend_interface(interface=HMACBackend)
class TestHMAC(object):
    def test_hmac_reject_unicode(self, backend):
        h = hmac.HMAC(b"mykey", hashes.SHA1(), backend=backend)
        with pytest.raises(TypeError):
            h.update(u"\u00FC")

    def test_hmac_algorithm_instance(self, backend):
        with pytest.raises(TypeError):
            hmac.HMAC(b"key", hashes.SHA1, backend=backend)

    def test_raises_after_finalize(self, backend):
        h = hmac.HMAC(b"key", hashes.SHA1(), backend=backend)
        h.finalize()

        with pytest.raises(AlreadyFinalized):
            h.update(b"foo")

        with pytest.raises(AlreadyFinalized):
            h.copy()

        with pytest.raises(AlreadyFinalized):
            h.finalize()

    def test_verify(self, backend):
        h = hmac.HMAC(b'', hashes.SHA1(), backend=backend)
        digest = h.finalize()

        h = hmac.HMAC(b'', hashes.SHA1(), backend=backend)
        h.verify(digest)

        with pytest.raises(AlreadyFinalized):
            h.verify(b'')

    def test_invalid_verify(self, backend):
        h = hmac.HMAC(b'', hashes.SHA1(), backend=backend)
        with pytest.raises(InvalidSignature):
            h.verify(b'')

        with pytest.raises(AlreadyFinalized):
            h.verify(b'')

    def test_verify_reject_unicode(self, backend):
        h = hmac.HMAC(b'', hashes.SHA1(), backend=backend)
        with pytest.raises(TypeError):
            h.verify(u'')

    def test_unsupported_hash(self, backend):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            hmac.HMAC(b"key", DummyHashAlgorithm(), backend)


def test_invalid_backend():
    pretend_backend = object()

    with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
        hmac.HMAC(b"key", hashes.SHA1(), pretend_backend)
