# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


from cryptography import exceptions, utils
from cryptography.hazmat.backends.openssl import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.sm2 import (
    SM2PrivateKey,
    SM2PublicKey,
    _SM2_MAX_KEY_SIZE,
    _SM2_MAX_SIG_SIZE,
)


class _SM2PublicKey(SM2PublicKey):
    def __init__(self, backend, ec_key_cdata, evp_pkey):
        self._backend = backend
        self._ec_key = ec_key_cdata
        self._evp_pkey = evp_pkey

        sn = ec._ec_key_curve_sn(backend, ec_key_cdata)
        self._curve = ec._sn_to_elliptic_curve(backend, sn)
        ec._mark_asn1_named_ec_curve(backend, ec_key_cdata)

    curve = utils.read_only_property("_curve")

    def _encode_point(self, format: serialization.PublicFormat) -> bytes:
        if format is serialization.PublicFormat.CompressedPoint:
            conversion = self._backend._lib.POINT_CONVERSION_COMPRESSED
        else:
            assert format is serialization.PublicFormat.UncompressedPoint
            conversion = self._backend._lib.POINT_CONVERSION_UNCOMPRESSED

        group = self._backend._lib.EC_KEY_get0_group(self._ec_key)
        self._backend.openssl_assert(group != self._backend._ffi.NULL)
        point = self._backend._lib.EC_KEY_get0_public_key(self._ec_key)
        self._backend.openssl_assert(point != self._backend._ffi.NULL)
        with self._backend._tmp_bn_ctx() as bn_ctx:
            buflen = self._backend._lib.EC_POINT_point2oct(
                group, point, conversion, self._backend._ffi.NULL, 0, bn_ctx
            )
            self._backend.openssl_assert(buflen > 0)
            buf = self._backend._ffi.new("char[]", buflen)
            res = self._backend._lib.EC_POINT_point2oct(
                group, point, conversion, buf, buflen, bn_ctx
            )
            self._backend.openssl_assert(buflen == res)

        return self._backend._ffi.buffer(buf)[:]

    def public_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PublicFormat,
    ) -> bytes:
        if (
            encoding is serialization.Encoding.X962
            or format is serialization.PublicFormat.CompressedPoint
            or format is serialization.PublicFormat.UncompressedPoint
        ):
            if encoding is not serialization.Encoding.X962 or format not in (
                serialization.PublicFormat.CompressedPoint,
                serialization.PublicFormat.UncompressedPoint,
            ):
                raise ValueError(
                    "X962 encoding must be used with CompressedPoint or "
                    "UncompressedPoint format"
                )

            return self._encode_point(format)
        else:
            return self._backend._public_key_bytes(
                encoding, format, self, self._evp_pkey, None
            )

    def verify(self, signature: bytes, data: bytes, user_id: bytes) -> None:
        evp_pkey_ctx = self._backend._lib.EVP_PKEY_CTX_new(
            self._evp_pkey, self._backend._ffi.NULL
        )
        self._backend.openssl_assert(evp_pkey_ctx != self._backend._ffi.NULL)
        evp_pkey_ctx = self._backend._ffi.gc(
            evp_pkey_ctx, self._backend._lib.EVP_PKEY_CTX_free
        )
        res = self._backend._lib.EVP_PKEY_CTX_set1_id(
            evp_pkey_ctx, user_id, len(user_id)
        )
        self._backend.openssl_assert(res == 1)

        evp_md_ctx = self._backend._lib.EVP_MD_CTX_new()
        self._backend.openssl_assert(evp_md_ctx != self._backend._ffi.NULL)
        evp_md_ctx = self._backend._ffi.gc(
            evp_md_ctx, self._backend._lib.EVP_MD_CTX_free
        )
        self._backend._lib.EVP_MD_CTX_set_pkey_ctx(evp_md_ctx, evp_pkey_ctx)

        res = self._backend._lib.EVP_DigestVerifyInit(
            evp_md_ctx,
            self._backend._ffi.NULL,
            self._backend._ffi.NULL,
            self._backend._ffi.NULL,
            self._evp_pkey,
        )
        self._backend.openssl_assert(res == 1)
        res = self._backend._lib.EVP_DigestVerify(
            evp_md_ctx, signature, len(signature), data, len(data)
        )
        if res != 1:
            self._backend._consume_errors()
            raise exceptions.InvalidSignature


class _SM2PrivateKey(SM2PrivateKey):
    def __init__(self, backend, ec_key_cdata, evp_pkey):
        self._backend = backend
        self._ec_key = ec_key_cdata
        self._evp_pkey = evp_pkey

        sn = ec._ec_key_curve_sn(backend, ec_key_cdata)
        self._curve = ec._sn_to_elliptic_curve(backend, sn)
        ec._mark_asn1_named_ec_curve(backend, ec_key_cdata)

    curve = utils.read_only_property("_curve")

    def public_key(self) -> SM2PublicKey:
        group = self._backend._lib.EC_KEY_get0_group(self._ec_key)
        self._backend.openssl_assert(group != self._backend._ffi.NULL)

        curve_nid = self._backend._lib.EC_GROUP_get_curve_name(group)
        public_ec_key = self._backend._ec_key_new_by_curve_nid(curve_nid)

        point = self._backend._lib.EC_KEY_get0_public_key(self._ec_key)
        self._backend.openssl_assert(point != self._backend._ffi.NULL)

        res = self._backend._lib.EC_KEY_set_public_key(public_ec_key, point)
        self._backend.openssl_assert(res == 1)

        evp_pkey = self._backend._ec_cdata_to_evp_pkey(public_ec_key)
        res = self._backend._lib.EVP_PKEY_set_alias_type(
            evp_pkey, self._backend._lib.EVP_PKEY_SM2
        )
        self._backend.openssl_assert(res == 1)

        return _SM2PublicKey(self._backend, public_ec_key, evp_pkey)

    def sign(self, data: bytes, user_id: bytes) -> bytes:
        evp_pkey_ctx = self._backend._lib.EVP_PKEY_CTX_new(
            self._evp_pkey, self._backend._ffi.NULL
        )
        self._backend.openssl_assert(evp_pkey_ctx != self._backend._ffi.NULL)
        evp_pkey_ctx = self._backend._ffi.gc(
            evp_pkey_ctx, self._backend._lib.EVP_PKEY_CTX_free
        )
        res = self._backend._lib.EVP_PKEY_CTX_set1_id(
            evp_pkey_ctx, user_id, len(user_id)
        )
        self._backend.openssl_assert(res == 1)

        evp_md_ctx = self._backend._lib.EVP_MD_CTX_new()
        self._backend.openssl_assert(evp_md_ctx != self._backend._ffi.NULL)
        evp_md_ctx = self._backend._ffi.gc(
            evp_md_ctx, self._backend._lib.EVP_MD_CTX_free
        )
        self._backend._lib.EVP_MD_CTX_set_pkey_ctx(evp_md_ctx, evp_pkey_ctx)

        res = self._backend._lib.EVP_DigestSignInit(
            evp_md_ctx,
            self._backend._ffi.NULL,
            self._backend._ffi.NULL,
            self._backend._ffi.NULL,
            self._evp_pkey,
        )
        self._backend.openssl_assert(res == 1)
        buf = self._backend._ffi.new("unsigned char[]", _SM2_MAX_SIG_SIZE)
        buflen = self._backend._ffi.new("size_t *", len(buf))
        res = self._backend._lib.EVP_DigestSign(
            evp_md_ctx, buf, buflen, data, len(data)
        )
        self._backend.openssl_assert(res == 1)
        return self._backend._ffi.buffer(buf, buflen[0])[:]

    def private_bytes(
        self,
        encoding: serialization.Encoding,
        format: serialization.PrivateFormat,
        encryption_algorithm: serialization.KeySerializationEncryption,
    ) -> bytes:
        return self._backend._private_key_bytes(
            encoding, format, encryption_algorithm, self, self._evp_pkey, None
        )
