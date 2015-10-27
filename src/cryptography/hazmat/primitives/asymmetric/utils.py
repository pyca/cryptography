# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import warnings

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, univ

import six

from cryptography import utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurve


class _DSSSigValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),
        namedtype.NamedType('s', univ.Integer())
    )


def decode_rfc6979_signature(signature):
    warnings.warn(
        "decode_rfc6979_signature is deprecated and will "
        "be removed in a future version, use decode_dss_signature instead "
        "instead.",
        utils.DeprecatedIn10,
        stacklevel=2
    )
    return decode_dss_signature(signature)


def decode_dss_signature(signature):
    try:
        data, remaining = decoder.decode(signature, asn1Spec=_DSSSigValue())
    except PyAsn1Error:
        raise ValueError("Invalid signature data. Unable to decode ASN.1")

    if remaining:
        raise ValueError(
            "The signature contains bytes after the end of the ASN.1 sequence."
        )

    r = int(data.getComponentByName('r'))
    s = int(data.getComponentByName('s'))
    return (r, s)


def encode_rfc6979_signature(r, s):
    warnings.warn(
        "encode_rfc6979_signature is deprecated and will "
        "be removed in a future version, use encode_dss_signature instead "
        "instead.",
        utils.DeprecatedIn10,
        stacklevel=2
    )
    return encode_dss_signature(r, s)


def encode_dss_signature(r, s):
    if (
        not isinstance(r, six.integer_types) or
        not isinstance(s, six.integer_types)
    ):
        raise ValueError("Both r and s must be integers")

    sig = _DSSSigValue()
    sig.setComponentByName('r', r)
    sig.setComponentByName('s', s)
    return encoder.encode(sig)


def encode_ec_point(curve, x, y):
    if not isinstance(curve, EllipticCurve):
        raise TypeError("curve must be an EllipticCurve instance")

    if x is None:
        raise ValueError("null points are not supported")
    else:
        # key_size is in bits. Convert to bytes and round up
        byte_length = (curve.key_size + 7) // 8
        return (
            b'\x04' + utils.int_to_bytes(x, byte_length) +
            utils.int_to_bytes(y, byte_length)
        )


def decode_ec_point(curve, data):
    if not isinstance(curve, EllipticCurve):
        raise TypeError("curve must be an EllipticCurve instance")

    if data == b'\x00':
        raise ValueError("null points are not supported")
    elif data.startswith(b'\x04'):
        # key_size is in bits. Convert to bytes and round up
        byte_length = (curve.key_size + 7) // 8
        if len(data) == 2 * byte_length + 1:
            return (utils.int_from_bytes(data[1:byte_length + 1], 'big'),
                    utils.int_from_bytes(data[byte_length + 1:], 'big'))
        else:
            raise ValueError('Invalid elliptic curve point data length')
    else:
        raise ValueError('Unsupported elliptic curve point type')
