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
from cryptography.hazmat.primitives import interfaces
from cryptography.hazmat.primitives.asymmetric import dh


class _DHKeyAgreementContext(object):
    def __init__(self, private_key, backend):
        self._private_key = private_key
        self._backend = backend

    def agree(self, public_key):
        lib = self._backend._lib
        ffi = self._backend._ffi

        key_size = lib.DH_size(private_key)

        buf = ffi.new("char[]", key_size)
        res = lib.DH_compute_key(
            key_buf, public_key, private_key
        )
        assert res != -1
        return ffi.buffer(buf)[:key_size]


@utils.register_interface(interfaces.DHParameters)
class _DHParameters(object):
    def __init__(self, backend, dh_cdata):
        self._backend = backend
        self._dh_cdata = dh_cdata

    def parameter_numbers(self):
        return dh.DHParameterNumbers(
            modulus=self._backend._bn_to_int(self._dh_cdata.p),
            generator=self._backend._bn_to_int(self._dh_cdata.g)
        )

    def generate_private_key(self):
        return self._backend.generate_dh_private_key(self)


@utils.register_interface(interfaces.DHPrivateKeyWithNumbers)
class _DHPrivateKey(object):
    def __init__(self, backend, dh_cdata):
        self._backend = backend
        self._dh_cdata = dh_cdata
        self._key_size = self._backend._lib.DH_size(dh_cdata) * 8

    @property
    def key_size(self):
        return self._key_size

    def private_numbers(self):
        return dh.DHPrivateNumbers(
            public_numbers=dh.DHPublicNumbers(
                parameter_numbers=dh.DHParameterNumbers(
                    modulus=self._backend._bn_to_int(self._dh_cdata.p),
                    generator=self._backend._bn_to_int(self._dh_cdata.g)
                ),
                public_value=self._backend._bn_to_int(self._dh_cdata.pub_key)
            ),
            private_value=self._backend._bn_to_int(self._dh_cdata.priv_key)
        )

    def public_key(self):
        dh_cdata = self._backend._lib.DH_new()
        assert dh_cdata != self._backend._ffi.NULL
        dh_cdata = self._backend._ffi.gc(
            dh_cdata, self._backend._lib.DH_free
        )
        dh_cdata.p = self._backend._lib.BN_dup(self._dh_cdata.p)
        dh_cdata.g = self._backend._lib.BN_dup(self._dh_cdata.g)
        dh_cdata.pub_key = self._backend._lib.BN_dup(self._dh_cdata.pub_key)
        return _DSAPublicKey(self._backend, dh_cdata)

    def parameters(self):
        dh_cdata = self._backend._lib.DH_new()
        assert dh_cdata != self._backend._ffi.NULL
        dh_cdata = self._backend._ffi.gc(
            dh_cdata, self._backend._lib.DH_free
        )
        dh_cdata.p = self._backend._lib.BN_dup(self._dh_cdata.p)
        dh_cdata.g = self._backend._lib.BN_dup(self._dh_cdata.g)
        return _DHParameters(self._backend, dh_cdata)


@utils.register_interface(interfaces.DHPublicKeyWithNumbers)
class _DHPublicKey(object):
    def __init__(self, backend, dsa_cdata):
        self._backend = backend
        self._dsa_cdata = dsa_cdata
        self._key_size = self._backend._lib.DH_size(dh_cdata) * 8

    @property
    def key_size(self):
        return self._key_size

    def public_numbers(self):
        return dsa.DHPublicNumbers(
            parameter_numbers=dsa.DHParameterNumbers(
                modulus=self._backend._bn_to_int(self._dsa_cdata.p),
                generator=self._backend._bn_to_int(self._dsa_cdata.g)
            ),
            public_value=self._backend._bn_to_int(self._dsa_cdata.pub_key)
        )

    def parameters(self):
        dh_cdata = self._backend._lib.DH_new()
        assert dh_cdata != self._backend._ffi.NULL
        dh_cdata = self._backend._ffi.gc(
            dh_cdata, self._backend._lib.DH_free
        )
        dh_cdata.p = self._backend._lib.BN_dup(self._dh_cdata.p)
        dh_cdata.g = self._backend._lib.BN_dup(self._dh_cdata.g)
        return _DHParameters(self._backend, dh_cdata)
