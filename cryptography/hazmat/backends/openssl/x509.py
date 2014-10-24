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

from pyasn1.codec.der import decoder

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.openssl.dsa import _DSAPublicKey
from cryptography.hazmat.backends.openssl.ec import _EllipticCurvePublicKey
from cryptography.hazmat.backends.openssl.rsa import _RSAPublicKey
from cryptography.hazmat.primitives import hashes, interfaces
from cryptography.hazmat.primitives.x509 import asn1extdef


class BC(object):
    def __init__(self, ca, pathlen):
        self.ca = ca  # boolean
        self.pathlen = pathlen  # integer


class IAP(object):
    def __init__(self, skipcerts):
        self.skipcerts = skipcerts  # integer


@utils.register_interface(interfaces.X509Certificate)
class _X509Certificate(object):
    def __init__(self, backend, x509):
        self._backend = backend
        self._x509 = x509
        self.extensions = []

        ext_count = self._backend._lib.X509_get_ext_count(self._x509)
        for i in range(0, ext_count):
            ext = self._backend._lib.X509_get_ext(self._x509, i)
            assert ext != self._backend._ffi.NULL
            length = self._backend._lib.i2d_X509_EXTENSION(
                ext, self._backend._ffi.NULL
            )
            assert length > 0
            buf = self._backend._ffi.new("unsigned char[]", length)
            buf_ptr = self._backend._ffi.new("unsigned char **", buf)
            res = self._backend._lib.i2d_X509_EXTENSION(ext, buf_ptr)
            assert res >= 0
            data = self._backend._ffi.buffer(buf, length)[:]
            decoded_ext, _ = decoder.decode(
                data, asn1Spec=asn1extdef.X509Extension()
            )
            oid = decoded_ext.getComponentByName('extnID')
            try:
                spec = asn1extdef.EXTENSION_MAPPING[oid]
                ext_bytes = bytes(decoded_ext.getComponentByName('extnValue'))
                processed = decoder.decode(ext_bytes, asn1Spec=spec())
                self.extensions.append(processed)
            except KeyError:
                print("unknown extension {0}".format(oid))
            except:
                import pdb
                pdb.set_trace()

        import pdb
        pdb.set_trace()

    def _create_bio(self):
        bio_method = self._backend._lib.BIO_s_mem()
        assert bio_method != self._backend._ffi.NULL
        bio = self._backend._lib.BIO_new(bio_method)
        assert bio != self._backend._ffi.NULL
        bio = self._backend._ffi.gc(bio, self._backend._lib.BIO_free)
        return bio

    def _read_bio(self, bio):
        buf = self._backend._ffi.new("char **")
        buf_len = self._backend._lib.BIO_get_mem_data(bio, buf)
        assert buf_len > 0
        assert buf[0] != self._backend._ffi.NULL
        return self._backend._ffi.buffer(buf[0], buf_len)[:]

    def fingerprint(self, algorithm):
        h = hashes.Hash(algorithm, self._backend)
        bio = self._create_bio()
        res = self._backend._lib.i2d_X509_bio(
            bio, self._x509
        )
        assert res == 1
        der = self._read_bio(bio)
        h.update(der)
        return h.finalize()

    @property
    def serial(self):
        asn1_int = self._backend._lib.X509_get_serialNumber(self._x509)
        assert asn1_int != self._backend._ffi.NULL
        bn = self._backend._lib.ASN1_INTEGER_to_BN(
            asn1_int, self._backend._ffi.NULL
        )
        assert bn != self._backend._ffi.NULL
        serial = self._backend._lib.BN_bn2hex(bn)
        assert serial != self._backend._ffi.NULL
        return self._backend._ffi.string(serial)

    @property
    def version(self):
        # TODO: this will return 0 indexed version. Do we want this?
        return self._backend._lib.X509_get_version(self._x509)

    def subject(self):
        pass

    def issuer(self):
        pass

    @property
    def signature_algorithm(self):
        pass

    def public_key(self):
        pkey = self._backend._lib.X509_get_pubkey(self._x509)
        assert pkey != self._backend._ffi.NULL
        pkey = self._backend._ffi.gc(pkey, self._backend._lib.EVP_PKEY_free)
        if pkey.type == self._backend._lib.EVP_PKEY_RSA:
            rsa_cdata = self._backend._lib.EVP_PKEY_get1_RSA(pkey)
            assert rsa_cdata != self._backend._ffi.NULL
            rsa_cdata = self._backend._ffi.gc(
                rsa_cdata, self._backend._lib.RSA_free
            )
            return _RSAPublicKey(self._backend, rsa_cdata)
        elif pkey.type == self._backend._lib.EVP_PKEY_DSA:
            dsa_cdata = self._backend._lib.EVP_PKEY_get1_DSA(pkey)
            assert dsa_cdata != self._backend._ffi.NULL
            dsa_cdata = self._backend._ffi.gc(
                dsa_cdata, self._backend._lib.DSA_free
            )
            return _DSAPublicKey(self._backend, dsa_cdata)
        elif (self._backend._lib.Cryptography_HAS_EC == 1 and
              pkey.type == self._backend._lib.EVP_PKEY_EC):
            ec_cdata = self._backend._lib.EVP_PKEY_get1_EC_KEY(pkey)
            assert ec_cdata != self._backend._ffi.NULL
            ec_cdata = self._backend._ffi.gc(
                ec_cdata, self._backend._lib.EC_KEY_free
            )
            return _EllipticCurvePublicKey(self._backend, ec_cdata)
        else:
            # TODO: ensure coverage
            raise UnsupportedAlgorithm("Unsupported key type.")

    @property
    def not_before(self):
        asn1_time = self._backend._lib.X509_get_notBefore(self._x509)
        return self._parse_asn1_time(asn1_time)

    @property
    def not_after(self):
        asn1_time = self._backend._lib.X509_get_notAfter(self._x509)
        return self._parse_asn1_time(asn1_time)

    def _parse_asn1_time(self, asn1_time):
        assert asn1_time != self._backend._ffi.NULL
        generalized_time = self._backend._lib.ASN1_TIME_to_generalizedtime(
            asn1_time, self._backend._ffi.NULL
        )
        assert generalized_time != self._backend._ffi.NULL
        generalized_time = self._backend._ffi.gc(
            generalized_time, self._backend._lib.ASN1_GENERALIZEDTIME_free
        )
        time = self._backend._ffi.string(
            self._backend._lib.ASN1_STRING_data(
                self._backend._ffi.cast("ASN1_STRING *", generalized_time)
            )
        )
        # TODO: pytz UTC timezone stuff
        return datetime.datetime.strptime(time[:-1], "%Y%m%d%H%M%S")
