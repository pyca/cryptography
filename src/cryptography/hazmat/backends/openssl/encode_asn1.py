# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


from cryptography import x509
from cryptography.x509.name import _ASN1Type


def _encode_asn1_int(backend, x):
    """
    Converts a python integer to an ASN1_INTEGER. The returned ASN1_INTEGER
    will not be garbage collected (to support adding them to structs that take
    ownership of the object). Be sure to register it for GC if it will be
    discarded after use.

    """
    # Convert Python integer to OpenSSL "bignum" in case value exceeds
    # machine's native integer limits (note: `int_to_bn` doesn't automatically
    # GC).
    i = backend._int_to_bn(x)
    i = backend._ffi.gc(i, backend._lib.BN_free)

    # Wrap in an ASN.1 integer.  Don't GC -- as documented.
    i = backend._lib.BN_to_ASN1_INTEGER(i, backend._ffi.NULL)
    backend.openssl_assert(i != backend._ffi.NULL)
    return i


def _encode_asn1_int_gc(backend, x):
    i = _encode_asn1_int(backend, x)
    i = backend._ffi.gc(i, backend._lib.ASN1_INTEGER_free)
    return i


def _encode_asn1_str(backend, data):
    """
    Create an ASN1_OCTET_STRING from a Python byte string.
    """
    s = backend._lib.ASN1_OCTET_STRING_new()
    res = backend._lib.ASN1_OCTET_STRING_set(s, data, len(data))
    backend.openssl_assert(res == 1)
    return s


def _encode_asn1_str_gc(backend, data):
    s = _encode_asn1_str(backend, data)
    s = backend._ffi.gc(s, backend._lib.ASN1_OCTET_STRING_free)
    return s


def _encode_name(backend, name):
    """
    The X509_NAME created will not be gc'd. Use _encode_name_gc if needed.
    """
    subject = backend._lib.X509_NAME_new()
    for rdn in name.rdns:
        set_flag = 0  # indicate whether to add to last RDN or create new RDN
        for attribute in rdn:
            name_entry = _encode_name_entry(backend, attribute)
            # X509_NAME_add_entry dups the object so we need to gc this copy
            name_entry = backend._ffi.gc(
                name_entry, backend._lib.X509_NAME_ENTRY_free
            )
            res = backend._lib.X509_NAME_add_entry(
                subject, name_entry, -1, set_flag
            )
            backend.openssl_assert(res == 1)
            set_flag = -1
    return subject


def _encode_name_gc(backend, attributes):
    subject = _encode_name(backend, attributes)
    subject = backend._ffi.gc(subject, backend._lib.X509_NAME_free)
    return subject


def _encode_name_entry(backend, attribute):
    # TODO: remove this entire func by completing extension encoding
    assert attribute._type not in (
        _ASN1Type.BMPString,
        _ASN1Type.UniversalString,
    )
    value = attribute.value.encode("utf8")

    obj = _txt2obj_gc(backend, attribute.oid.dotted_string)

    name_entry = backend._lib.X509_NAME_ENTRY_create_by_OBJ(
        backend._ffi.NULL, obj, attribute._type.value, value, len(value)
    )
    return name_entry


def _txt2obj(backend, name):
    """
    Converts a Python string with an ASN.1 object ID in dotted form to a
    ASN1_OBJECT.
    """
    name = name.encode("ascii")
    obj = backend._lib.OBJ_txt2obj(name, 1)
    backend.openssl_assert(obj != backend._ffi.NULL)
    return obj


def _txt2obj_gc(backend, name):
    obj = _txt2obj(backend, name)
    obj = backend._ffi.gc(obj, backend._lib.ASN1_OBJECT_free)
    return obj


_CRLREASONFLAGS = {
    x509.ReasonFlags.key_compromise: 1,
    x509.ReasonFlags.ca_compromise: 2,
    x509.ReasonFlags.affiliation_changed: 3,
    x509.ReasonFlags.superseded: 4,
    x509.ReasonFlags.cessation_of_operation: 5,
    x509.ReasonFlags.certificate_hold: 6,
    x509.ReasonFlags.privilege_withdrawn: 7,
    x509.ReasonFlags.aa_compromise: 8,
}
