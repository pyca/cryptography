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
import warnings

from cryptography import utils, x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes


def _obj2txt(backend, obj):
    # Set to 80 on the recommendation of
    # https://www.openssl.org/docs/crypto/OBJ_nid2ln.html#return_values
    buf_len = 80
    buf = backend._ffi.new("char[]", buf_len)
    res = backend._lib.OBJ_obj2txt(buf, buf_len, obj, 1)
    assert res > 0
    return backend._ffi.buffer(buf, res)[:].decode()


def _build_x509_name(backend, x509_name):
    count = backend._lib.X509_NAME_entry_count(x509_name)
    attributes = []
    for x in range(count):
        entry = backend._lib.X509_NAME_get_entry(x509_name, x)
        obj = backend._lib.X509_NAME_ENTRY_get_object(entry)
        assert obj != backend._ffi.NULL
        data = backend._lib.X509_NAME_ENTRY_get_data(entry)
        assert data != backend._ffi.NULL
        buf = backend._ffi.new("unsigned char **")
        res = backend._lib.ASN1_STRING_to_UTF8(buf, data)
        assert res >= 0
        assert buf[0] != backend._ffi.NULL
        buf = backend._ffi.gc(
            buf, lambda buffer: backend._lib.OPENSSL_free(buffer[0])
        )
        value = backend._ffi.buffer(buf[0], res)[:].decode('utf8')
        oid = _obj2txt(backend, obj)
        attributes.append(
            x509.NameAttribute(
                x509.ObjectIdentifier(oid), value
            )
        )

    return x509.Name(attributes)


@utils.register_interface(x509.Certificate)
class _Certificate(object):
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
            return x509.Version.v1
        elif version == 2:
            return x509.Version.v3
        else:
            raise x509.InvalidVersion(
                "{0} is not a valid X509 version".format(version), version
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
        ).decode("ascii")
        return datetime.datetime.strptime(time, "%Y%m%d%H%M%SZ")

    @property
    def issuer(self):
        issuer = self._backend._lib.X509_get_issuer_name(self._x509)
        assert issuer != self._backend._ffi.NULL
        return _build_x509_name(self._backend, issuer)

    @property
    def subject(self):
        subject = self._backend._lib.X509_get_subject_name(self._x509)
        assert subject != self._backend._ffi.NULL
        return _build_x509_name(self._backend, subject)

    @property
    def signature_hash_algorithm(self):
        oid = _obj2txt(self._backend, self._x509.sig_alg.algorithm)
        try:
            return x509._SIG_OIDS_TO_HASH[oid]
        except KeyError:
            raise UnsupportedAlgorithm(
                "Signature algorithm OID:{0} not recognized".format(oid)
            )

    @property
    def extensions(self):
        extensions = []
        seen_oids = set()
        extcount = self._backend._lib.X509_get_ext_count(self._x509)
        for i in range(0, extcount):
            ext = self._backend._lib.X509_get_ext(self._x509, i)
            assert ext != self._backend._ffi.NULL
            crit = self._backend._lib.X509_EXTENSION_get_critical(ext)
            critical = crit == 1
            oid = x509.ObjectIdentifier(_obj2txt(self._backend, ext.object))
            if oid in seen_oids:
                raise x509.DuplicateExtension(
                    "Duplicate {0} extension found".format(oid), oid
                )
            elif oid == x509.OID_BASIC_CONSTRAINTS:
                value = self._build_basic_constraints(ext)
            elif oid == x509.OID_SUBJECT_KEY_IDENTIFIER:
                value = self._build_subject_key_identifier(ext)
            elif oid == x509.OID_KEY_USAGE and critical:
                # TODO: remove this obviously.
                warnings.warn(
                    "Extension support is not fully implemented. A key usage "
                    "extension with the critical flag was seen and IGNORED."
                )
                seen_oids.add(oid)
                continue
            elif critical:
                raise x509.UnsupportedExtension(
                    "{0} is not currently supported".format(oid), oid
                )
            else:
                # Unsupported non-critical extension, silently skipping for now
                seen_oids.add(oid)
                continue

            seen_oids.add(oid)
            extensions.append(x509.Extension(oid, critical, value))

        return x509.Extensions(extensions)

    def _build_basic_constraints(self, ext):
        bc_st = self._backend._lib.X509V3_EXT_d2i(ext)
        assert bc_st != self._backend._ffi.NULL
        basic_constraints = self._backend._ffi.cast(
            "BASIC_CONSTRAINTS *", bc_st
        )
        basic_constraints = self._backend._ffi.gc(
            basic_constraints, self._backend._lib.BASIC_CONSTRAINTS_free
        )
        # The byte representation of an ASN.1 boolean true is \xff. OpenSSL
        # chooses to just map this to its ordinal value, so true is 255 and
        # false is 0.
        ca = basic_constraints.ca == 255
        if basic_constraints.pathlen == self._backend._ffi.NULL:
            path_length = None
        else:
            bn = self._backend._lib.ASN1_INTEGER_to_BN(
                basic_constraints.pathlen, self._backend._ffi.NULL
            )
            assert bn != self._backend._ffi.NULL
            bn = self._backend._ffi.gc(bn, self._backend._lib.BN_free)
            path_length = self._backend._bn_to_int(bn)

        return x509.BasicConstraints(ca, path_length)

    def _build_subject_key_identifier(self, ext):
        asn1_string = self._backend._lib.X509V3_EXT_d2i(ext)
        assert asn1_string != self._backend._ffi.NULL
        asn1_string = self._backend._ffi.cast(
            "ASN1_OCTET_STRING *", asn1_string
        )
        asn1_string = self._backend._ffi.gc(
            asn1_string, self._backend._lib.ASN1_OCTET_STRING_free
        )
        return x509.SubjectKeyIdentifier(
            self._backend._ffi.buffer(asn1_string.data, asn1_string.length)[:]
        )


@utils.register_interface(x509.CertificateSigningRequest)
class _CertificateSigningRequest(object):
    def __init__(self, backend, x509_req):
        self._backend = backend
        self._x509_req = x509_req

    def public_key(self):
        pkey = self._backend._lib.X509_REQ_get_pubkey(self._x509_req)
        assert pkey != self._backend._ffi.NULL
        pkey = self._backend._ffi.gc(pkey, self._backend._lib.EVP_PKEY_free)
        return self._backend._evp_pkey_to_public_key(pkey)

    @property
    def subject(self):
        subject = self._backend._lib.X509_REQ_get_subject_name(self._x509_req)
        assert subject != self._backend._ffi.NULL
        return _build_x509_name(self._backend, subject)

    @property
    def signature_hash_algorithm(self):
        oid = _obj2txt(self._backend, self._x509_req.sig_alg.algorithm)
        try:
            return x509._SIG_OIDS_TO_HASH[oid]
        except KeyError:
            raise UnsupportedAlgorithm(
                "Signature algorithm OID:{0} not recognized".format(oid)
            )
