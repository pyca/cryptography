# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import datetime
import warnings

from cryptography import utils, x509
from cryptography.hazmat.backends.openssl.decode_asn1 import (
    _asn1_string_to_bytes,
)
from cryptography.hazmat.backends.openssl.encode_asn1 import (
    _txt2obj_gc,
)
from cryptography.x509.name import _ASN1Type


# This exists for pyOpenSSL compatibility and SHOULD NOT BE USED
# WE WILL REMOVE THIS VERY SOON.
def _Certificate(backend, x509) -> x509.Certificate:  # noqa: N802
    warnings.warn(
        "This version of cryptography contains a temporary pyOpenSSL "
        "fallback path. Upgrade pyOpenSSL now.",
        utils.DeprecatedIn35,
    )
    return backend._ossl2cert(x509)


class _CertificateSigningRequest(x509.CertificateSigningRequest):
    def __init__(self, backend, x509_req):
        self._backend = backend
        self._x509_req = x509_req

    def get_attribute_for_oid(self, oid: x509.ObjectIdentifier) -> bytes:
        obj = _txt2obj_gc(self._backend, oid.dotted_string)
        pos = self._backend._lib.X509_REQ_get_attr_by_OBJ(
            self._x509_req, obj, -1
        )
        if pos == -1:
            raise x509.AttributeNotFound(
                "No {} attribute was found".format(oid), oid
            )

        attr = self._backend._lib.X509_REQ_get_attr(self._x509_req, pos)
        self._backend.openssl_assert(attr != self._backend._ffi.NULL)
        # We don't support multiple valued attributes for now.
        self._backend.openssl_assert(
            self._backend._lib.X509_ATTRIBUTE_count(attr) == 1
        )
        asn1_type = self._backend._lib.X509_ATTRIBUTE_get0_type(attr, 0)
        self._backend.openssl_assert(asn1_type != self._backend._ffi.NULL)
        # We need this to ensure that our C type cast is safe.
        # Also this should always be a sane string type, but we'll see if
        # that is true in the real world...
        if asn1_type.type not in (
            _ASN1Type.UTF8String.value,
            _ASN1Type.PrintableString.value,
            _ASN1Type.IA5String.value,
        ):
            raise ValueError(
                "OID {} has a disallowed ASN.1 type: {}".format(
                    oid, asn1_type.type
                )
            )

        data = self._backend._lib.X509_ATTRIBUTE_get0_data(
            attr, 0, asn1_type.type, self._backend._ffi.NULL
        )
        self._backend.openssl_assert(data != self._backend._ffi.NULL)
        # This cast is safe iff we assert on the type above to ensure
        # that it is always a type of ASN1_STRING
        data = self._backend._ffi.cast("ASN1_STRING *", data)
        return _asn1_string_to_bytes(self._backend, data)


class _RawRevokedCertificate(x509.RevokedCertificate):
    def __init__(
        self,
        serial_number: int,
        revocation_date: datetime.datetime,
        extensions: x509.Extensions,
    ):
        self._serial_number = serial_number
        self._revocation_date = revocation_date
        self._extensions = extensions

    @property
    def serial_number(self) -> int:
        return self._serial_number

    @property
    def revocation_date(self) -> datetime.datetime:
        return self._revocation_date

    @property
    def extensions(self) -> x509.Extensions:
        return self._extensions
