# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.openssl.decode_asn1 import (
    _OCSP_REQ_EXT_PARSER, _asn1_integer_to_int, _asn1_string_to_bytes, _obj2txt
)
from cryptography.hazmat.primitives import serialization
from cryptography.x509.ocsp import OCSPRequest, _OIDS_TO_HASH


def _issuer_key_hash(backend, cert_id):
    key_hash = backend._ffi.new("ASN1_OCTET_STRING **")
    res = backend._lib.OCSP_id_get0_info(
        backend._ffi.NULL, backend._ffi.NULL,
        key_hash, backend._ffi.NULL, cert_id
    )
    backend.openssl_assert(res == 1)
    backend.openssl_assert(key_hash[0] != backend._ffi.NULL)
    return _asn1_string_to_bytes(backend, key_hash[0])


def _issuer_name_hash(backend, cert_id):
    name_hash = backend._ffi.new("ASN1_OCTET_STRING **")
    res = backend._lib.OCSP_id_get0_info(
        name_hash, backend._ffi.NULL,
        backend._ffi.NULL, backend._ffi.NULL, cert_id
    )
    backend.openssl_assert(res == 1)
    backend.openssl_assert(name_hash[0] != backend._ffi.NULL)
    return _asn1_string_to_bytes(backend, name_hash[0])


def _serial_number(backend, cert_id):
    num = backend._ffi.new("ASN1_INTEGER **")
    res = backend._lib.OCSP_id_get0_info(
        backend._ffi.NULL, backend._ffi.NULL,
        backend._ffi.NULL, num, cert_id
    )
    backend.openssl_assert(res == 1)
    backend.openssl_assert(num[0] != backend._ffi.NULL)
    return _asn1_integer_to_int(backend, num[0])


def _hash_algorithm(backend, cert_id):
    asn1obj = backend._ffi.new("ASN1_OBJECT **")
    res = backend._lib.OCSP_id_get0_info(
        backend._ffi.NULL, asn1obj,
        backend._ffi.NULL, backend._ffi.NULL, cert_id
    )
    backend.openssl_assert(res == 1)
    backend.openssl_assert(asn1obj[0] != backend._ffi.NULL)
    oid = _obj2txt(backend, asn1obj[0])
    try:
        return _OIDS_TO_HASH[oid]
    except KeyError:
        raise UnsupportedAlgorithm(
            "Signature algorithm OID: {0} not recognized".format(oid)
        )


@utils.register_interface(OCSPRequest)
class _OCSPRequest(object):
    def __init__(self, backend, ocsp_request):
        if backend._lib.OCSP_request_onereq_count(ocsp_request) > 1:
            raise NotImplementedError(
                'OCSP request contains more than one request'
            )
        self._backend = backend
        self._ocsp_request = ocsp_request
        self._request = self._backend._lib.OCSP_request_onereq_get0(
            self._ocsp_request, 0
        )
        self._backend.openssl_assert(self._request != self._backend._ffi.NULL)
        self._cert_id = self._backend._lib.OCSP_onereq_get0_id(self._request)
        self._backend.openssl_assert(self._cert_id != self._backend._ffi.NULL)

    @property
    def issuer_key_hash(self):
        return _issuer_key_hash(self._backend, self._cert_id)

    @property
    def issuer_name_hash(self):
        return _issuer_name_hash(self._backend, self._cert_id)

    @property
    def serial_number(self):
        return _serial_number(self._backend, self._cert_id)

    @property
    def hash_algorithm(self):
        return _hash_algorithm(self._backend, self._cert_id)

    @utils.cached_property
    def extensions(self):
        return _OCSP_REQ_EXT_PARSER.parse(self._backend, self._ocsp_request)

    def public_bytes(self, encoding):
        if encoding is not serialization.Encoding.DER:
            raise ValueError(
                "The only allowed encoding value is Encoding.DER"
            )

        bio = self._backend._create_mem_bio_gc()
        res = self._backend._lib.i2d_OCSP_REQUEST_bio(bio, self._ocsp_request)
        self._backend.openssl_assert(res > 0)
        return self._backend._read_mem_bio(bio)
