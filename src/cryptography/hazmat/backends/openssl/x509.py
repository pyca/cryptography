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

import datetime

from cryptography import utils, x509
from cryptography.hazmat.primitives import hashes


@utils.register_interface(x509.X509Certificate)
class _X509Certificate(object):
    def __init__(self, backend, x509):
        self._backend = backend
        self._x509 = x509

    def fingerprint(self, algorithm):
        h = hashes.Hash(algorithm, self._backend)
        bio = self._backend._create_mem_bio()
        res = self._backend._lib.i2d_X509_bio(
            bio, self._x509
        )
        assert res == 1
        der = self._backend._read_mem_bio(bio)
        h.update(der)
        return h.finalize()

    @property
    def version(self):
        version = self._backend._lib.X509_get_version(self._x509)
        if version == 0:
            return x509.X509Version.v1
        elif version == 2:
            return x509.X509Version.v3
        else:
            raise x509.InvalidX509Version(
                "{0} is not a valid X509 version".format(version)
            )

    @property
    def serial(self):
        asn1_int = self._backend._lib.X509_get_serialNumber(self._x509)
        assert asn1_int != self._backend._ffi.NULL
        bn = self._backend._lib.ASN1_INTEGER_to_BN(
            asn1_int, self._backend._ffi.NULL
        )
        assert bn != self._backend._ffi.NULL
        bn = self._backend._ffi.gc(bn, self._backend._lib.BN_free)
        return self._backend._bn_to_int(bn)

    def public_key(self):
        pkey = self._backend._lib.X509_get_pubkey(self._x509)
        assert pkey != self._backend._ffi.NULL
        pkey = self._backend._ffi.gc(pkey, self._backend._lib.EVP_PKEY_free)
        # The following check is to find ECDSA certificates with unnamed
        # curves and raise an error for now.
        if (
            self._backend._lib.Cryptography_HAS_EC == 1 and
            pkey.type == self._backend._lib.EVP_PKEY_EC
        ):
            ec_cdata = self._backend._lib.EVP_PKEY_get1_EC_KEY(pkey)
            assert ec_cdata != self._backend._ffi.NULL
            ec_cdata = self._backend._ffi.gc(
                ec_cdata, self._backend._lib.EC_KEY_free
            )
            group = self._backend._lib.EC_KEY_get0_group(ec_cdata)
            assert group != self._backend._ffi.NULL
            nid = self._backend._lib.EC_GROUP_get_curve_name(group)
            if nid == self._backend._lib.NID_undef:
                raise NotImplementedError(
                    "ECDSA certificates without named curves are unsupported "
                    "at this time"
                )

        return self._backend._evp_pkey_to_public_key(pkey)

    @property
    def not_valid_before(self):
        asn1_time = self._backend._lib.X509_get_notBefore(self._x509)
        return self._parse_asn1_time(asn1_time)

    @property
    def not_valid_after(self):
        asn1_time = self._backend._lib.X509_get_notAfter(self._x509)
        return self._parse_asn1_time(asn1_time)

    def _parse_asn1_time(self, asn1_time):
        bio = self._backend._create_mem_bio()
        res = self._backend._lib.ASN1_TIME_print(bio, asn1_time)
        assert res == 1
        time = self._backend._read_mem_bio(bio).decode("ascii")
        return datetime.datetime.strptime(time, "%b %d %H:%M:%S %Y GMT")
