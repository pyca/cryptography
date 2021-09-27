# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


from cryptography import x509


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


def _asn1_string_to_bytes(backend, asn1_string):
    return backend._ffi.buffer(asn1_string.data, asn1_string.length)[:]


def _asn1_string_to_utf8(backend, asn1_string) -> str:
    buf = backend._ffi.new("unsigned char **")
    res = backend._lib.ASN1_STRING_to_UTF8(buf, asn1_string)
    backend.openssl_assert(res >= 0)
    backend.openssl_assert(buf[0] != backend._ffi.NULL)
    buf = backend._ffi.gc(
        buf, lambda buffer: backend._lib.OPENSSL_free(buffer[0])
    )
    return backend._ffi.buffer(buf[0], res)[:].decode("utf8")
