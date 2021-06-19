# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import datetime
import typing

from cryptography import x509
from cryptography.x509.name import _ASN1_TYPE_TO_ENUM


def _obj2txt(backend, obj):
    # Set to 80 on the recommendation of
    # https://www.openssl.org/docs/crypto/OBJ_nid2ln.html#return_values
    #
    # But OIDs longer than this occur in real life (e.g. Active
    # Directory makes some very long OIDs).  So we need to detect
    # and properly handle the case where the default buffer is not
    # big enough.
    #
    buf_len = 80
    buf = backend._ffi.new("char[]", buf_len)

    # 'res' is the number of bytes that *would* be written if the
    # buffer is large enough.  If 'res' > buf_len - 1, we need to
    # alloc a big-enough buffer and go again.
    res = backend._lib.OBJ_obj2txt(buf, buf_len, obj, 1)
    if res > buf_len - 1:  # account for terminating null byte
        buf_len = res + 1
        buf = backend._ffi.new("char[]", buf_len)
        res = backend._lib.OBJ_obj2txt(buf, buf_len, obj, 1)
    backend.openssl_assert(res > 0)
    return backend._ffi.buffer(buf, res)[:].decode()


def _decode_x509_name_entry(backend, x509_name_entry):
    obj = backend._lib.X509_NAME_ENTRY_get_object(x509_name_entry)
    backend.openssl_assert(obj != backend._ffi.NULL)
    data = backend._lib.X509_NAME_ENTRY_get_data(x509_name_entry)
    backend.openssl_assert(data != backend._ffi.NULL)
    value = _asn1_string_to_utf8(backend, data)
    oid = _obj2txt(backend, obj)
    type = _ASN1_TYPE_TO_ENUM[data.type]

    return x509.NameAttribute(x509.ObjectIdentifier(oid), value, type)


def _decode_x509_name(backend, x509_name):
    count = backend._lib.X509_NAME_entry_count(x509_name)
    attributes = []
    prev_set_id = -1
    for x in range(count):
        entry = backend._lib.X509_NAME_get_entry(x509_name, x)
        attribute = _decode_x509_name_entry(backend, entry)
        set_id = backend._lib.X509_NAME_ENTRY_set(entry)
        if set_id != prev_set_id:
            attributes.append({attribute})
        else:
            # is in the same RDN a previous entry
            attributes[-1].add(attribute)
        prev_set_id = set_id

    return x509.Name(x509.RelativeDistinguishedName(rdn) for rdn in attributes)


class _X509ExtensionParser(object):
    def __init__(self, backend, ext_count, get_ext, rust_callback):
        self.ext_count = ext_count
        self.get_ext = get_ext
        self.rust_callback = rust_callback
        self._backend = backend

    def parse(self, x509_obj):
        extensions: typing.List[x509.Extension[x509.ExtensionType]] = []
        seen_oids = set()
        for i in range(self.ext_count(x509_obj)):
            ext = self.get_ext(x509_obj, i)
            self._backend.openssl_assert(ext != self._backend._ffi.NULL)
            crit = self._backend._lib.X509_EXTENSION_get_critical(ext)
            critical = crit == 1
            oid = x509.ObjectIdentifier(
                _obj2txt(
                    self._backend,
                    self._backend._lib.X509_EXTENSION_get_object(ext),
                )
            )
            if oid in seen_oids:
                raise x509.DuplicateExtension(
                    "Duplicate {} extension found".format(oid), oid
                )

            # Try to parse this with the rust callback first
            oid_ptr = self._backend._lib.X509_EXTENSION_get_object(ext)
            oid_der_bytes = self._backend._ffi.buffer(
                self._backend._lib.Cryptography_OBJ_get0_data(oid_ptr),
                self._backend._lib.Cryptography_OBJ_length(oid_ptr),
            )[:]
            data = self._backend._lib.X509_EXTENSION_get_data(ext)
            data_bytes = _asn1_string_to_bytes(self._backend, data)
            ext_obj = self.rust_callback(oid_der_bytes, data_bytes)
            if ext_obj is None:
                ext_obj = x509.UnrecognizedExtension(oid, data_bytes)

            extensions.append(x509.Extension(oid, critical, ext_obj))
            seen_oids.add(oid)

        return x509.Extensions(extensions)


_DISTPOINT_TYPE_FULLNAME = 0
_DISTPOINT_TYPE_RELATIVENAME = 1

#    CRLReason ::= ENUMERATED {
#        unspecified             (0),
#        keyCompromise           (1),
#        cACompromise            (2),
#        affiliationChanged      (3),
#        superseded              (4),
#        cessationOfOperation    (5),
#        certificateHold         (6),
#             -- value 7 is not used
#        removeFromCRL           (8),
#        privilegeWithdrawn      (9),
#        aACompromise           (10) }
_CRL_ENTRY_REASON_CODE_TO_ENUM = {
    0: x509.ReasonFlags.unspecified,
    1: x509.ReasonFlags.key_compromise,
    2: x509.ReasonFlags.ca_compromise,
    3: x509.ReasonFlags.affiliation_changed,
    4: x509.ReasonFlags.superseded,
    5: x509.ReasonFlags.cessation_of_operation,
    6: x509.ReasonFlags.certificate_hold,
    8: x509.ReasonFlags.remove_from_crl,
    9: x509.ReasonFlags.privilege_withdrawn,
    10: x509.ReasonFlags.aa_compromise,
}


_CRL_ENTRY_REASON_ENUM_TO_CODE = {
    x509.ReasonFlags.unspecified: 0,
    x509.ReasonFlags.key_compromise: 1,
    x509.ReasonFlags.ca_compromise: 2,
    x509.ReasonFlags.affiliation_changed: 3,
    x509.ReasonFlags.superseded: 4,
    x509.ReasonFlags.cessation_of_operation: 5,
    x509.ReasonFlags.certificate_hold: 6,
    x509.ReasonFlags.remove_from_crl: 8,
    x509.ReasonFlags.privilege_withdrawn: 9,
    x509.ReasonFlags.aa_compromise: 10,
}


def _asn1_integer_to_int(backend, asn1_int):
    bn = backend._lib.ASN1_INTEGER_to_BN(asn1_int, backend._ffi.NULL)
    backend.openssl_assert(bn != backend._ffi.NULL)
    bn = backend._ffi.gc(bn, backend._lib.BN_free)
    return backend._bn_to_int(bn)


def _asn1_string_to_bytes(backend, asn1_string):
    return backend._ffi.buffer(asn1_string.data, asn1_string.length)[:]


def _asn1_string_to_ascii(backend, asn1_string):
    return _asn1_string_to_bytes(backend, asn1_string).decode("ascii")


def _asn1_string_to_utf8(backend, asn1_string) -> str:
    buf = backend._ffi.new("unsigned char **")
    res = backend._lib.ASN1_STRING_to_UTF8(buf, asn1_string)
    if res == -1:
        raise ValueError(
            "Unsupported ASN1 string type. Type: {}".format(asn1_string.type)
        )

    backend.openssl_assert(buf[0] != backend._ffi.NULL)
    buf = backend._ffi.gc(
        buf, lambda buffer: backend._lib.OPENSSL_free(buffer[0])
    )
    return backend._ffi.buffer(buf[0], res)[:].decode("utf8")


def _parse_asn1_time(backend, asn1_time):
    backend.openssl_assert(asn1_time != backend._ffi.NULL)
    generalized_time = backend._lib.ASN1_TIME_to_generalizedtime(
        asn1_time, backend._ffi.NULL
    )
    if generalized_time == backend._ffi.NULL:
        raise ValueError(
            "Couldn't parse ASN.1 time as generalizedtime {!r}".format(
                _asn1_string_to_bytes(backend, asn1_time)
            )
        )

    generalized_time = backend._ffi.gc(
        generalized_time, backend._lib.ASN1_GENERALIZEDTIME_free
    )
    return _parse_asn1_generalized_time(backend, generalized_time)


def _parse_asn1_generalized_time(backend, generalized_time):
    time = _asn1_string_to_ascii(
        backend, backend._ffi.cast("ASN1_STRING *", generalized_time)
    )
    return datetime.datetime.strptime(time, "%Y%m%d%H%M%SZ")
