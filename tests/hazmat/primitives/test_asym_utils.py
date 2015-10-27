# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import binascii

import pytest

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature, decode_ec_point, decode_rfc6979_signature,
    encode_dss_signature, encode_ec_point, encode_rfc6979_signature
)


def test_deprecated_rfc6979_signature():
    sig = pytest.deprecated_call(encode_rfc6979_signature, 1, 1)
    assert sig == b"0\x06\x02\x01\x01\x02\x01\x01"
    decoded = pytest.deprecated_call(decode_rfc6979_signature, sig)
    assert decoded == (1, 1)


def test_dss_signature():
    sig = encode_dss_signature(1, 1)
    assert sig == b"0\x06\x02\x01\x01\x02\x01\x01"
    assert decode_dss_signature(sig) == (1, 1)

    r_s1 = (
        1037234182290683143945502320610861668562885151617,
        559776156650501990899426031439030258256861634312
    )
    sig2 = encode_dss_signature(*r_s1)
    assert sig2 == (
        b'0-\x02\x15\x00\xb5\xaf0xg\xfb\x8bT9\x00\x13\xccg\x02\r\xdf\x1f,\x0b'
        b'\x81\x02\x14b\r;"\xabP1D\x0c>5\xea\xb6\xf4\x81)\x8f\x9e\x9f\x08'
    )
    assert decode_dss_signature(sig2) == r_s1

    sig3 = encode_dss_signature(0, 0)
    assert sig3 == b"0\x06\x02\x01\x00\x02\x01\x00"
    assert decode_dss_signature(sig3) == (0, 0)

    sig4 = encode_dss_signature(-1, 0)
    assert sig4 == b"0\x06\x02\x01\xFF\x02\x01\x00"
    assert decode_dss_signature(sig4) == (-1, 0)


def test_encode_dss_non_integer():
    with pytest.raises(ValueError):
        encode_dss_signature("h", 3)

    with pytest.raises(ValueError):
        encode_dss_signature("3", "2")

    with pytest.raises(ValueError):
        encode_dss_signature(3, "h")

    with pytest.raises(ValueError):
        encode_dss_signature(3.3, 1.2)

    with pytest.raises(ValueError):
        encode_dss_signature("hello", "world")


def test_decode_dss_trailing_bytes():
    with pytest.raises(ValueError):
        decode_dss_signature(b"0\x06\x02\x01\x01\x02\x01\x01\x00\x00\x00")


def test_decode_dss_invalid_asn1():
    with pytest.raises(ValueError):
        # This byte sequence has an invalid ASN.1 sequence length as well as
        # an invalid integer length for the second integer.
        decode_dss_signature(b"0\x07\x02\x01\x01\x02\x02\x01")

    with pytest.raises(ValueError):
        # This is the BER "end-of-contents octets," which older versions of
        # pyasn1 are wrongly willing to return from top-level DER decoding.
        decode_dss_signature(b"\x00\x00")


def test_encode_ec_point_none():
    with pytest.raises(ValueError):
        encode_ec_point(ec.SECP384R1(), None, 100)


def test_encode_wrong_curve_type():
    with pytest.raises(TypeError):
        encode_ec_point("notacurve", 3, 4)


def test_encode_ec_point():
    # secp256r1 point
    x = int(
        '233ea3b0027127084cd2cd336a13aeef69c598d8af61369a36454a17c6c22aec', 16
    )
    y = int(
        '3ea2c10a84153862be4ec82940f0543f9ba866af9751a6ee79d38460b35f442e', 16
    )
    data = encode_ec_point(ec.SECP256R1(), x, y)
    assert data == binascii.unhexlify(
        "04233ea3b0027127084cd2cd336a13aeef69c598d8af61369a36454a17c6c22aec3ea"
        "2c10a84153862be4ec82940f0543f9ba866af9751a6ee79d38460b35f442e"
    )


def test_decode_ec_point_none():
    with pytest.raises(ValueError):
        decode_ec_point(ec.SECP384R1(), b"\x00")


def test_decode_ec_point():
    # secp256r1 point
    data = binascii.unhexlify(
        "04233ea3b0027127084cd2cd336a13aeef69c598d8af61369a36454a17c6c22aec3ea"
        "2c10a84153862be4ec82940f0543f9ba866af9751a6ee79d38460b35f442e"
    )
    x, y = decode_ec_point(ec.SECP256R1(), data)
    assert x == int(
        '233ea3b0027127084cd2cd336a13aeef69c598d8af61369a36454a17c6c22aec', 16
    )
    assert y == int(
        '3ea2c10a84153862be4ec82940f0543f9ba866af9751a6ee79d38460b35f442e', 16
    )


def test_decode_ec_point_invalid_length():
    bad_data = binascii.unhexlify(
        "04233ea3b0027127084cd2cd336a13aeef69c598d8af61369a36454a17c6c22aec3ea"
        "2c10a84153862be4ec82940f0543f9ba866af9751a6ee79d38460"
    )
    with pytest.raises(ValueError):
        decode_ec_point(ec.SECP384R1(), bad_data)


def test_decode_ec_point_unsupported_point_type():
    # set to point type 2.
    unsupported_type = binascii.unhexlify(
        "02233ea3b0027127084cd2cd336a13aeef69c598d8af61369a36454a17c6c22aec3e"
    )
    with pytest.raises(ValueError):
        decode_ec_point(ec.SECP256R1(), unsupported_type)


def test_decode_wrong_curve_type():
    with pytest.raises(TypeError):
        decode_ec_point("notacurve", b"\x02data")
