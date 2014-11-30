# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from pyasn1.codec.der import decoder, encoder
from pyasn1.type import namedtype, univ


class _DSSSigValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),
        namedtype.NamedType('s', univ.Integer())
    )


def decode_rfc6979_signature(signature):
    data = decoder.decode(signature, asn1Spec=_DSSSigValue())
    if data[1]:
        raise ValueError(
            "The signature contains bytes after the end of the ASN.1 sequence."
        )
    r = int(data[0].getComponentByName('r'))
    s = int(data[0].getComponentByName('s'))
    return (r, s)


def encode_rfc6979_signature(r, s):
    sig = _DSSSigValue()
    sig.setComponentByName('r', r)
    sig.setComponentByName('s', s)
    return encoder.encode(sig)
