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

import binascii

import pretend

import pytest

import six

from cryptography import utils
from cryptography.exceptions import AlreadyFinalized, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, hmac, interfaces


@utils.register_interface(interfaces.HashAlgorithm)
class UnsupportedDummyHash(object):
        name = "unsupported-dummy-hash"


@pytest.mark.hmac
class TestHMAC(object):
    @pytest.mark.supported(
        only_if=lambda backend: backend.hmac_supported(hashes.MD5),
        skip_message="Does not support MD5",
    )
    def test_hmac_copy(self, backend):
        key = b"ab"
        h = hmac.HMAC(binascii.unhexlify(key), hashes.MD5(), backend=backend)
        h_copy = h.copy()
        assert h != h_copy
        assert h._ctx != h_copy._ctx

    def test_hmac_reject_unicode(self, backend):
        h = hmac.HMAC(b"mykey", hashes.SHA1(), backend=backend)
        with pytest.raises(TypeError):
            h.update(six.u("\u00FC"))

    def test_copy_backend_object(self):
        pretend_hmac = pretend.stub()
        pretend_backend = pretend.stub(hmacs=pretend_hmac)
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

    def test_unsupported_hash(self, backend):
        with pytest.raises(UnsupportedAlgorithm):
            hmac.HMAC(b"key", UnsupportedDummyHash(), backend)
