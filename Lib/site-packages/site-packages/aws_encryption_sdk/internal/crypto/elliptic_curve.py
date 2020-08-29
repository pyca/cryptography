# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Contains elliptic curve functionality."""
import logging
from collections import namedtuple

import six
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature, encode_dss_signature
from cryptography.utils import InterfaceNotImplemented, int_from_bytes, int_to_bytes, verify_interface

from ...exceptions import NotSupportedError
from ..str_ops import to_bytes

_LOGGER = logging.getLogger(__name__)


# Curve parameter values are included strictly as a temporary measure
#  until they can be rolled into the cryptography.io library.
# Expanded values from http://www.secg.org/sec2-v2.pdf
_ECCCurveParameters = namedtuple("_ECCCurveParameters", ["p", "a", "b", "order"])
_ECC_CURVE_PARAMETERS = {
    "secp256r1": _ECCCurveParameters(
        p=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
        a=0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
        b=0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
        order=0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    ),
    "secp384r1": _ECCCurveParameters(
        p=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF,
        a=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC,
        b=0xB3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF,
        order=0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973,
    ),
    "secp521r1": _ECCCurveParameters(
        p=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF,  # noqa pylint: disable=line-too-long
        a=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC,  # noqa pylint: disable=line-too-long
        b=0x0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00,  # noqa pylint: disable=line-too-long
        order=0x01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409,  # noqa pylint: disable=line-too-long
    ),
}


def _ecc_static_length_signature(key, algorithm, digest):
    """Calculates an elliptic curve signature with a static length using pre-calculated hash.

    :param key: Elliptic curve private key
    :type key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
    :param algorithm: Master algorithm to use
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :param bytes digest: Pre-calculated hash digest
    :returns: Signature with required length
    :rtype: bytes
    """
    pre_hashed_algorithm = ec.ECDSA(Prehashed(algorithm.signing_hash_type()))
    signature = b""
    while len(signature) != algorithm.signature_len:
        _LOGGER.debug(
            "Signature length %d is not desired length %d.  Recalculating.", len(signature), algorithm.signature_len
        )
        signature = key.sign(digest, pre_hashed_algorithm)
        if len(signature) != algorithm.signature_len:
            # Most of the time, a signature of the wrong length can be fixed
            # by negating s in the signature relative to the group order.
            _LOGGER.debug(
                "Signature length %d is not desired length %d.  Negating s.", len(signature), algorithm.signature_len
            )
            r, s = decode_dss_signature(signature)
            s = _ECC_CURVE_PARAMETERS[algorithm.signing_algorithm_info.name].order - s
            signature = encode_dss_signature(r, s)
    return signature


def _ecc_encode_compressed_point(private_key):
    """Encodes a compressed elliptic curve point
        as described in SEC-1 v2 section 2.3.3
        http://www.secg.org/sec1-v2.pdf

    :param private_key: Private key from which to extract point data
    :type private_key: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey
    :returns: Encoded compressed elliptic curve point
    :rtype: bytes
    :raises NotSupportedError: for non-prime curves
    """
    # key_size is in bits. Convert to bytes and round up
    byte_length = (private_key.curve.key_size + 7) // 8
    public_numbers = private_key.public_key().public_numbers()
    y_map = [b"\x02", b"\x03"]
    # If curve in prime field.
    if private_key.curve.name.startswith("secp"):
        y_order = public_numbers.y % 2
        y = y_map[y_order]
    else:
        raise NotSupportedError("Non-prime curves are not supported at this time")
    return y + int_to_bytes(public_numbers.x, byte_length)


def _ecc_decode_compressed_point(curve, compressed_point):
    """Decodes a compressed elliptic curve point
        as described in SEC-1 v2 section 2.3.4
        http://www.secg.org/sec1-v2.pdf

    :param curve: Elliptic curve type to generate
    :type curve: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve
    :param bytes compressed_point: Encoded compressed elliptic curve point
    :returns: X and Y coordinates from compressed point
    :rtype: tuple of longs
    :raises NotSupportedError: for non-prime curves, unsupported prime curves, and points at infinity
    """
    if not compressed_point:
        raise NotSupportedError("Points at infinity are not allowed")
    y_order_map = {b"\x02": 0, b"\x03": 1}
    raw_x = compressed_point[1:]
    raw_x = to_bytes(raw_x)
    x = int_from_bytes(raw_x, "big")
    raw_y = compressed_point[0]
    # In Python3, bytes index calls return int values rather than strings
    if isinstance(raw_y, six.integer_types):
        raw_y = six.b(chr(raw_y))
    elif isinstance(raw_y, six.string_types):
        raw_y = six.b(raw_y)
    y_order = y_order_map[raw_y]
    # If curve in prime field.
    if curve.name.startswith("secp"):
        try:
            params = _ECC_CURVE_PARAMETERS[curve.name]
        except KeyError:
            raise NotSupportedError("Curve {name} is not supported at this time".format(name=curve.name))
        alpha = (pow(x, 3, params.p) + (params.a * x % params.p) + params.b) % params.p
        # Only works for p % 4 == 3 at this time.
        # This is the case for all currently supported algorithms.
        # This will need to be expanded if curves which do not match this are added.
        #  Python-ecdsa has these algorithms implemented.  Copy or reference?
        #  https://en.wikipedia.org/wiki/Tonelli%E2%80%93Shanks_algorithm
        #  Handbook of Applied Cryptography, algorithms 3.34 - 3.39
        if params.p % 4 == 3:
            beta = pow(alpha, (params.p + 1) // 4, params.p)
        else:
            raise NotSupportedError("S not 1 :: Curve not supported at this time")
        if beta % 2 == y_order:
            y = beta
        else:
            y = params.p - beta
    else:
        raise NotSupportedError("Non-prime curves are not supported at this time")
    return x, y


def _ecc_public_numbers_from_compressed_point(curve, compressed_point):
    """Decodes a compressed elliptic curve point
        as described in SEC-1 v2 section 2.3.3
        and returns a PublicNumbers instance
        based on the decoded point.
        http://www.secg.org/sec1-v2.pdf

    :param curve: Elliptic curve type to generate
    :type curve: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurve
    :param bytes compressed_point: Encoded compressed elliptic curve point
    :returns: EllipticCurvePublicNumbers instance generated from compressed point and curve
    :rtype: cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePublicNumbers
    """
    x, y = _ecc_decode_compressed_point(curve, compressed_point)
    return ec.EllipticCurvePublicNumbers(x=x, y=y, curve=curve)


def generate_ecc_signing_key(algorithm):
    """Returns an ECC signing key.

    :param algorithm: Algorithm object which determines what signature to generate
    :type algorithm: aws_encryption_sdk.identifiers.Algorithm
    :returns: Generated signing key
    :raises NotSupportedError: if signing algorithm is not supported on this platform
    """
    try:
        verify_interface(ec.EllipticCurve, algorithm.signing_algorithm_info)
        return ec.generate_private_key(curve=algorithm.signing_algorithm_info(), backend=default_backend())
    except InterfaceNotImplemented:
        raise NotSupportedError("Unsupported signing algorithm info")
