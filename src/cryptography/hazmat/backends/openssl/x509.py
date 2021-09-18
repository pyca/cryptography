# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


import datetime
import operator
import typing
import warnings

from cryptography import utils, x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat._oid import _SIG_OIDS_TO_HASH
from cryptography.hazmat.backends.openssl import dsa, ec, rsa
from cryptography.hazmat.backends.openssl.decode_asn1 import (
    _asn1_integer_to_int,
    _asn1_string_to_bytes,
    _decode_x509_name,
    _obj2txt,
    _parse_asn1_time,
)
from cryptography.hazmat.backends.openssl.encode_asn1 import (
    _encode_asn1_int_gc,
    _txt2obj_gc,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.base import PUBLIC_KEY_TYPES
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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _CertificateSigningRequest):
            return NotImplemented

        self_bytes = self.public_bytes(serialization.Encoding.DER)
        other_bytes = other.public_bytes(serialization.Encoding.DER)
        return self_bytes == other_bytes

    def __ne__(self, other: object) -> bool:
        return not self == other

    def __hash__(self) -> int:
        return hash(self.public_bytes(serialization.Encoding.DER))

    def public_key(self) -> PUBLIC_KEY_TYPES:
        pkey = self._backend._lib.X509_REQ_get_pubkey(self._x509_req)
        self._backend.openssl_assert(pkey != self._backend._ffi.NULL)
        pkey = self._backend._ffi.gc(pkey, self._backend._lib.EVP_PKEY_free)
        return self._backend._evp_pkey_to_public_key(pkey)

    @property
    def subject(self) -> x509.Name:
        subject = self._backend._lib.X509_REQ_get_subject_name(self._x509_req)
        self._backend.openssl_assert(subject != self._backend._ffi.NULL)
        return _decode_x509_name(self._backend, subject)

    @property
    def signature_hash_algorithm(
        self,
    ) -> typing.Optional[hashes.HashAlgorithm]:
        oid = self.signature_algorithm_oid
        try:
            return _SIG_OIDS_TO_HASH[oid]
        except KeyError:
            raise UnsupportedAlgorithm(
                "Signature algorithm OID:{} not recognized".format(oid)
            )

    @property
    def signature_algorithm_oid(self) -> x509.ObjectIdentifier:
        alg = self._backend._ffi.new("X509_ALGOR **")
        self._backend._lib.X509_REQ_get0_signature(
            self._x509_req, self._backend._ffi.NULL, alg
        )
        self._backend.openssl_assert(alg[0] != self._backend._ffi.NULL)
        oid = _obj2txt(self._backend, alg[0].algorithm)
        return x509.ObjectIdentifier(oid)

    @utils.cached_property
    def extensions(self) -> x509.Extensions:
        x509_exts = self._backend._lib.X509_REQ_get_extensions(self._x509_req)
        x509_exts = self._backend._ffi.gc(
            x509_exts,
            lambda x: self._backend._lib.sk_X509_EXTENSION_pop_free(
                x,
                self._backend._ffi.addressof(
                    self._backend._lib._original_lib, "X509_EXTENSION_free"
                ),
            ),
        )
        return self._backend._csr_extension_parser.parse(x509_exts)

    def public_bytes(self, encoding: serialization.Encoding) -> bytes:
        bio = self._backend._create_mem_bio_gc()
        if encoding is serialization.Encoding.PEM:
            res = self._backend._lib.PEM_write_bio_X509_REQ(
                bio, self._x509_req
            )
        elif encoding is serialization.Encoding.DER:
            res = self._backend._lib.i2d_X509_REQ_bio(bio, self._x509_req)
        else:
            raise TypeError("encoding must be an item from the Encoding enum")

        self._backend.openssl_assert(res == 1)
        return self._backend._read_mem_bio(bio)

    @property
    def tbs_certrequest_bytes(self) -> bytes:
        pp = self._backend._ffi.new("unsigned char **")
        res = self._backend._lib.i2d_re_X509_REQ_tbs(self._x509_req, pp)
        self._backend.openssl_assert(res > 0)
        pp = self._backend._ffi.gc(
            pp, lambda pointer: self._backend._lib.OPENSSL_free(pointer[0])
        )
        return self._backend._ffi.buffer(pp[0], res)[:]

    @property
    def signature(self) -> bytes:
        sig = self._backend._ffi.new("ASN1_BIT_STRING **")
        self._backend._lib.X509_REQ_get0_signature(
            self._x509_req, sig, self._backend._ffi.NULL
        )
        self._backend.openssl_assert(sig[0] != self._backend._ffi.NULL)
        return _asn1_string_to_bytes(self._backend, sig[0])

    @property
    def is_signature_valid(self) -> bool:
        pkey = self._backend._lib.X509_REQ_get_pubkey(self._x509_req)
        self._backend.openssl_assert(pkey != self._backend._ffi.NULL)
        pkey = self._backend._ffi.gc(pkey, self._backend._lib.EVP_PKEY_free)
        res = self._backend._lib.X509_REQ_verify(self._x509_req, pkey)

        if res != 1:
            self._backend._consume_errors()
            return False

        return True

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
