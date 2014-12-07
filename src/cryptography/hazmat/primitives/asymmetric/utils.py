# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from pyasn1.codec.der import decoder, encoder
from pyasn1.error import PyAsn1Error
from pyasn1.type import namedtype, univ


class _DSSSigValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),
        namedtype.NamedType('s', univ.Integer())
    )


def decode_rfc6979_signature(signature):
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
    try:
        sig = _DSSSigValue()
        sig.setComponentByName('r', r)
        sig.setComponentByName('s', s)
    except PyAsn1Error:
        raise ValueError("Both r and s must be integers")

    return encoder.encode(sig)
