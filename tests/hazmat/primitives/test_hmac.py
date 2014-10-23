# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import pretend

import pytest

import six

from cryptography import utils
from cryptography.exceptions import (
    AlreadyFinalized, InvalidSignature, _Reasons
)
from cryptography.hazmat.backends.interfaces import HMACBackend
from cryptography.hazmat.primitives import hashes, hmac, interfaces

from .utils import generate_base_hmac_test
from ...utils import raises_unsupported_algorithm


@utils.register_interface(interfaces.HashAlgorithm)
class UnsupportedDummyHash(object):
    name = "unsupported-dummy-hash"


@pytest.mark.supported(
    only_if=lambda backend: backend.hmac_supported(hashes.MD5()),
    skip_message="Does not support MD5",
)
@pytest.mark.hmac
class TestHMACCopy(object):
    test_copy = generate_base_hmac_test(
        hashes.MD5(),
    )


@pytest.mark.hmac
class TestHMAC(object):
    def test_hmac_reject_unicode(self, backend):
        h = hmac.HMAC(b"mykey", hashes.SHA1(), backend=backend)
        with pytest.raises(TypeError):
            h.update(six.u("\u00FC"))

    def test_copy_backend_object(self):
        @utils.register_interface(HMACBackend)
        class PretendBackend(object):
            pass

        pretend_backend = PretendBackend()
        copied_ctx = pretend.stub()
        pretend_ctx = pretend.stub(copy=lambda: copied_ctx)
        h = hmac.HMAC(b"key", hashes.SHA1(), backend=pretend_backend,
                      ctx=pretend_ctx)
        assert h._backend is pretend_backend
        assert h.copy()._backend is pretend_backend

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
            h.verify(six.u(''))

    def test_unsupported_hash(self, backend):
        with raises_unsupported_algorithm(_Reasons.UNSUPPORTED_HASH):
            hmac.HMAC(b"key", UnsupportedDummyHash(), backend)


def test_invalid_backend():
    pretend_backend = object()

    with raises_unsupported_algorithm(_Reasons.BACKEND_MISSING_INTERFACE):
        hmac.HMAC(b"key", hashes.SHA1(), pretend_backend)
