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

from cryptography import utils
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, interfaces


@utils.register_interface(interfaces.AsymmetricVerificationContext)
class _DSAVerificationContext(object):
    def __init__(self, backend, public_key, signature, algorithm):
        self._backend = backend
        self._public_key = public_key
        self._signature = signature
        self._algorithm = algorithm

        self._hash_ctx = hashes.Hash(self._algorithm, self._backend)

    def update(self, data):
        self._hash_ctx.update(data)

    def verify(self):
        self._dsa_cdata = self._backend._dsa_cdata_from_public_key(
            self._public_key)
        self._dsa_cdata = self._backend._ffi.gc(self._dsa_cdata,
                                                self._backend._lib.DSA_free)

        data_to_verify = self._hash_ctx.finalize()

        # The first parameter passed to DSA_verify is unused by OpenSSL but
        # must be an integer.
        res = self._backend._lib.DSA_verify(
            0, data_to_verify, len(data_to_verify), self._signature,
            len(self._signature), self._dsa_cdata)

        if res != 1:
            errors = self._backend._consume_errors()
            assert errors
            if res == -1:
                assert errors[0].lib == self._backend._lib.ERR_LIB_ASN1

            raise InvalidSignature


@utils.register_interface(interfaces.AsymmetricSignatureContext)
class _DSASignatureContext(object):
    def __init__(self, backend, private_key, algorithm):
        self._backend = backend
        self._private_key = private_key
        self._algorithm = algorithm
        self._hash_ctx = hashes.Hash(self._algorithm, self._backend)
        self._dsa_cdata = self._backend._dsa_cdata_from_private_key(
            self._private_key)
        self._dsa_cdata = self._backend._ffi.gc(self._dsa_cdata,
                                                self._backend._lib.DSA_free)

    def update(self, data):
        self._hash_ctx.update(data)

    def finalize(self):
        data_to_sign = self._hash_ctx.finalize()
        sig_buf_len = self._backend._lib.DSA_size(self._dsa_cdata)
        sig_buf = self._backend._ffi.new("unsigned char[]", sig_buf_len)
        buflen = self._backend._ffi.new("unsigned int *")

        # The first parameter passed to DSA_sign is unused by OpenSSL but
        # must be an integer.
        res = self._backend._lib.DSA_sign(
            0, data_to_sign, len(data_to_sign), sig_buf,
            buflen, self._dsa_cdata)
        assert res == 1
        assert buflen[0]

        return self._backend._ffi.buffer(sig_buf)[:buflen[0]]
