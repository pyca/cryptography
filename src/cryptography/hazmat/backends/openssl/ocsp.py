# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import operator

from cryptography import utils
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.backends.openssl.decode_asn1 import (
    _asn1_integer_to_int, _asn1_string_to_bytes, _obj2txt
)
from cryptography.hazmat.primitives import serialization
from cryptography.x509.ocsp import OCSPRequest, Request, _OIDS_TO_HASH


@utils.register_interface(Request)
class _Request(object):
    def __init__(self, backend, ocsp_request, request):
        self._backend = backend
        self._ocsp_request = ocsp_request
        self._request = request
        self._cert_id = self._backend._lib.OCSP_onereq_get0_id(self._request)
        self._backend.openssl_assert(self._cert_id != self._backend._ffi.NULL)

    @property
    def issuer_key_hash(self):
        key_hash = self._backend._ffi.new("ASN1_OCTET_STRING **")
        res = self._backend._lib.OCSP_id_get0_info(
            self._backend._ffi.NULL, self._backend._ffi.NULL,
            key_hash, self._backend._ffi.NULL, self._cert_id
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(key_hash[0] != self._backend._ffi.NULL)
        return _asn1_string_to_bytes(self._backend, key_hash[0])

    @property
    def issuer_name_hash(self):
        name_hash = self._backend._ffi.new("ASN1_OCTET_STRING **")
        res = self._backend._lib.OCSP_id_get0_info(
            name_hash, self._backend._ffi.NULL,
            self._backend._ffi.NULL, self._backend._ffi.NULL, self._cert_id
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(name_hash[0] != self._backend._ffi.NULL)
        return _asn1_string_to_bytes(self._backend, name_hash[0])

    @property
    def serial_number(self):
        num = self._backend._ffi.new("ASN1_INTEGER **")
        res = self._backend._lib.OCSP_id_get0_info(
            self._backend._ffi.NULL, self._backend._ffi.NULL,
            self._backend._ffi.NULL, num, self._cert_id
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(num[0] != self._backend._ffi.NULL)
        return _asn1_integer_to_int(self._backend, num[0])

    @property
    def hash_algorithm(self):
        asn1obj = self._backend._ffi.new("ASN1_OBJECT **")
        res = self._backend._lib.OCSP_id_get0_info(
            self._backend._ffi.NULL, asn1obj,
            self._backend._ffi.NULL, self._backend._ffi.NULL, self._cert_id
        )
        self._backend.openssl_assert(res == 1)
        self._backend.openssl_assert(asn1obj[0] != self._backend._ffi.NULL)
        oid = _obj2txt(self._backend, asn1obj[0])
        try:
            return _OIDS_TO_HASH[oid]
        except KeyError:
            raise UnsupportedAlgorithm(
                "Signature algorithm OID: {0} not recognized".format(oid)
            )


@utils.register_interface(OCSPRequest)
class _OCSPRequest(object):
    def __init__(self, backend, ocsp_request):
        self._backend = backend
        self._ocsp_request = ocsp_request

    def __len__(self):
        return self._backend._lib.OCSP_request_onereq_count(self._ocsp_request)

    def _request(self, idx):
        request = self._backend._lib.OCSP_request_onereq_get0(
            self._ocsp_request, idx
        )
        self._backend.openssl_assert(request != self._backend._ffi.NULL)
        return _Request(self._backend, self._ocsp_request, request)

    def public_bytes(self, encoding):
        if encoding is not serialization.Encoding.DER:
            raise ValueError(
                "The only allowed encoding value is Encoding.DER"
            )

        bio = self._backend._create_mem_bio_gc()
        res = self._backend._lib.i2d_OCSP_REQUEST_bio(bio, self._ocsp_request)
        self._backend.openssl_assert(res > 0)
        return self._backend._read_mem_bio(bio)

    def __iter__(self):
        for i in range(len(self)):
            yield self._request(i)

    def __getitem__(self, idx):
        if isinstance(idx, slice):
            start, stop, step = idx.indices(len(self))
            return [self._request(i) for i in range(start, stop, step)]
        else:
            idx = operator.index(idx)
            if idx < 0:
                idx += len(self)
            if not 0 <= idx < len(self):
                raise IndexError
            return self._request(idx)
