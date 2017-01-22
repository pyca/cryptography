# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import warnings

from asn1crypto.core import Integer, Sequence

import six

from cryptography import utils
from cryptography.hazmat.primitives import hashes


class _DSSSigValue(Sequence):
    _fields = [
        ('r', Integer),
        ('s', Integer)
    ]


def decode_rfc6979_signature(signature):
    warnings.warn(
        "decode_rfc6979_signature is deprecated and will "
        "be removed in a future version, use decode_dss_signature instead.",
        utils.DeprecatedIn10,
        stacklevel=2
    )
    return decode_dss_signature(signature)


def decode_dss_signature(signature):
    try:
        data = _DSSSigValue.load(signature).native
    except ValueError:
        # We raise another ValueError to provide a generic message
        # after the already informative asn1crypto ValueError.
        raise ValueError("Invalid signature data. Unable to decode ASN.1")

    r = data['r']
    s = data['s']
    return r, s


def encode_rfc6979_signature(r, s):
    warnings.warn(
        "encode_rfc6979_signature is deprecated and will "
        "be removed in a future version, use encode_dss_signature instead.",
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
    sig['r'] = r
    sig['s'] = s
    return sig.dump()


class Prehashed(object):
    def __init__(self, algorithm):
        if not isinstance(algorithm, hashes.HashAlgorithm):
            raise TypeError("Expected instance of HashAlgorithm.")

        self._algorithm = algorithm
        self._digest_size = algorithm.digest_size

    digest_size = utils.read_only_property("_digest_size")
