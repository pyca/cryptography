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

from cryptography.hazmat.primitives import hashes, hmac

from .utils import generate_base_hmac_test


class TestHMAC(object):
    test_copy = generate_base_hmac_test(
        hashes.MD5(),
        only_if=lambda backend: backend.hashes.supported(hashes.MD5),
        skip_message="Does not support MD5",
    )

    def test_hmac_reject_unicode(self, backend):
        h = hmac.HMAC(b"mykey", hashes.SHA1(), backend=backend)
        with pytest.raises(TypeError):
            h.update(six.u("\u00FC"))

    def test_copy_backend_object(self):
        pretend_hmac = pretend.stub(copy_ctx=lambda a: True)
        pretend_backend = pretend.stub(hmacs=pretend_hmac)
        pretend_ctx = pretend.stub()
        h = hmac.HMAC(b"key", hashes.SHA1(), backend=pretend_backend,
                      ctx=pretend_ctx)
        assert h._backend is pretend_backend
        assert h.copy()._backend is pretend_backend

    def test_hmac_algorithm_instance(self):
        with pytest.raises(TypeError):
            hmac.HMAC(b"key", hashes.SHA1)
