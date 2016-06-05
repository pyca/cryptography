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
from cryptography.hazmat.primitives.asymmetric import dh


def _dh_cdata_to_parameters(dh_cdata, backend):
    lib = backend._lib
    ffi = backend._ffi

    param_cdata = lib.DH_new()
    assert param_cdata != ffi.NULL
    param_cdata = ffi.gc(param_cdata, lib.DH_free)

    p = ffi.new("BIGNUM **")
    g = ffi.new("BIGNUM **")
    lib.DH_get0_pqg(dh_cdata, p, ffi.NULL, g)
    assert p[0] != ffi.NULL
    assert g[0] != ffi.NULL
    p_dup = lib.BN_dup(p[0])
    g_dup = lib.BN_dup(g[0])
    assert p_dup != ffi.NULL
    assert g_dup != ffi.NULL
    res = lib.DH_set0_pqg(param_cdata, p_dup, ffi.NULL, g_dup)
    assert res == 1

    return _DHParameters(backend, param_cdata)


@utils.register_interface(dh.DHParametersWithSerialization)
class _DHParameters(object):
    def __init__(self, backend, dh_cdata):
        self._backend = backend
        self._dh_cdata = dh_cdata

    def parameter_numbers(self):
        p = self._backend._ffi.new("BIGNUM **")
        g = self._backend._ffi.new("BIGNUM **")
        self._backend._lib.DH_get0_pqg(self._dh_cdata,
                                       p, self._backend._ffi.NULL, g)
        assert p[0] != self._backend._ffi.NULL
        assert g[0] != self._backend._ffi.NULL
        return dh.DHParameterNumbers(
            p=self._backend._bn_to_int(p[0]),
            g=self._backend._bn_to_int(g[0])
        )

    def generate_private_key(self):
        return self._backend.generate_dh_private_key(self)


def _handle_dh_compute_key_error(errors, backend):
    lib = backend._lib

    assert errors[0][1:] == (
        lib.ERR_LIB_DH,
        lib.DH_F_COMPUTE_KEY,
        lib.DH_R_INVALID_PUBKEY
    )

    raise ValueError("Public key value is invalid for this exchange.")


@utils.register_interface(dh.DHPrivateKeyWithSerialization)
class _DHPrivateKey(object):
    def __init__(self, backend, dh_cdata):
        self._backend = backend
        self._dh_cdata = dh_cdata
        self._key_size = self._backend._lib.DH_size(dh_cdata)

    @property
    def key_size(self):
        return self._key_size * 8

    def private_numbers(self):
        p = self._backend._ffi.new("BIGNUM **")
        g = self._backend._ffi.new("BIGNUM **")
        self._backend._lib.DH_get0_pqg(self._dh_cdata,
                                       p, self._backend._ffi.NULL, g)
        assert p[0] != self._backend._ffi.NULL
        assert g[0] != self._backend._ffi.NULL
        pub_key = self._backend._ffi.new("BIGNUM **")
        priv_key = self._backend._ffi.new("BIGNUM **")
        self._backend._lib.DH_get0_key(self._dh_cdata, pub_key, priv_key)
        assert pub_key[0] != self._backend._ffi.NULL
        assert priv_key[0] != self._backend._ffi.NULL
        return dh.DHPrivateNumbers(
            public_numbers=dh.DHPublicNumbers(
                parameter_numbers=dh.DHParameterNumbers(
                    p=self._backend._bn_to_int(p[0]),
                    g=self._backend._bn_to_int(g[0])
                ),
                y=self._backend._bn_to_int(pub_key[0])
            ),
            x=self._backend._bn_to_int(priv_key[0])
        )

    def exchange(self, peer_public_key):

        buf = self._backend._ffi.new("char[]", self._key_size)
        res = self._backend._lib.DH_compute_key(
            buf,
            self._backend._int_to_bn(peer_public_key.public_numbers().y),
            self._dh_cdata
        )

        if res == -1:
            errors = self._backend._consume_errors()
            return _handle_dh_compute_key_error(errors, self._backend)
        else:
            assert res >= 1

            key = self._backend._ffi.buffer(buf)[:res]
            pad = self._key_size - len(key)

            if pad > 0:
                key = (b"\x00" * pad) + key

            return key

    def public_key(self):
        dh_cdata = self._backend._lib.DH_new()
        assert dh_cdata != self._backend._ffi.NULL
        dh_cdata = self._backend._ffi.gc(
            dh_cdata, self._backend._lib.DH_free
        )

        p = self._backend._ffi.new("BIGNUM **")
        g = self._backend._ffi.new("BIGNUM **")
        self._backend._lib.DH_get0_pqg(self._dh_cdata,
                                       p, self._backend._ffi.NULL, g)
        assert p[0] != self._backend._ffi.NULL
        assert g[0] != self._backend._ffi.NULL
        p_dup = self._backend._lib.BN_dup(p[0])
        g_dup = self._backend._lib.BN_dup(g[0])
        assert p_dup != self._backend._ffi.NULL
        assert g_dup != self._backend._ffi.NULL
        pub_key = self._backend._ffi.new("BIGNUM **")
        self._backend._lib.DH_get0_key(self._dh_cdata,
                                       pub_key, self._backend._ffi.NULL)
        assert pub_key[0] != self._backend._ffi.NULL
        pub_key_dup = self._backend._lib.BN_dup(pub_key[0])
        assert pub_key_dup != self._backend._ffi.NULL

        res = self._backend._lib.DH_set0_pqg(dh_cdata,
                                             p_dup,
                                             self._backend._ffi.NULL, g_dup)
        assert res == 1

        res = self._backend._lib.DH_set0_key(dh_cdata,
                                             pub_key_dup,
                                             self._backend._ffi.NULL)
        assert res == 1

        return _DHPublicKey(self._backend, dh_cdata)

    def parameters(self):
        return _dh_cdata_to_parameters(self._dh_cdata, self._backend)


@utils.register_interface(dh.DHPublicKeyWithSerialization)
class _DHPublicKey(object):
    def __init__(self, backend, dh_cdata):
        self._backend = backend
        self._dh_cdata = dh_cdata
        self._key_size = self._backend._lib.DH_size(dh_cdata) * 8

    @property
    def key_size(self):
        return self._key_size

    def public_numbers(self):
        p = self._backend._ffi.new("BIGNUM **")
        g = self._backend._ffi.new("BIGNUM **")
        self._backend._lib.DH_get0_pqg(self._dh_cdata,
                                       p, self._backend._ffi.NULL, g)
        assert p[0] != self._backend._ffi.NULL
        assert g[0] != self._backend._ffi.NULL
        pub_key = self._backend._ffi.new("BIGNUM **")
        self._backend._lib.DH_get0_key(self._dh_cdata,
                                       pub_key, self._backend._ffi.NULL)
        assert pub_key[0] != self._backend._ffi.NULL
        return dh.DHPublicNumbers(
            parameter_numbers=dh.DHParameterNumbers(
                p=self._backend._bn_to_int(p[0]),
                g=self._backend._bn_to_int(g[0])
            ),
            y=self._backend._bn_to_int(pub_key[0])
        )

    def parameters(self):
        return _dh_cdata_to_parameters(self._dh_cdata, self._backend)
