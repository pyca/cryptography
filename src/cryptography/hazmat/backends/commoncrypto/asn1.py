# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import six


_ASN1_NULL = b"\x05\x00"
_RSA_OID = b"\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01"


def _int_to_asn1_int(i):
    if i == 0:
        return b'\x02\x01\x00'
    if i < 0:
        raise ValueError("Only positive integers are supported.")
    packed = _pack_int(i)
    if ord(packed[0]) > 127:
        # ASN.1 integers are stored big endian two's complement, so add a byte
        # if the ordinal value of the last byte is over 0x7f.
        packed = b"\x00" + packed
    return b"\x02" + _pack_length(len(packed)) + packed


def _pack_int(i):
    result = []
    while i:
        result.append(six.int2byte(i & 0xFF))
        i >>= 8
    result.reverse()
    return b''.join(result)


def _pack_length(i):
    """
    For the definite form, if the length is less than 128, you just use a
    single byte, with the high bit set to zero. Otherwise the high bit is set
    to one, and the low seven bits set to the length of length. The length is
    then encoded in that many bytes.
    """
    if i < 128:
        return six.int2byte(i)
    else:
        packed = _pack_int(i)
        encoded_length = 128 | len(packed)
        return _pack_int(encoded_length) + packed


def _asn1_seq(l):
    combined = b"".join(l)
    return b"\x30" + _pack_length(len(combined)) + combined


def _asn1_bit_string(d):
    return b"\x03" + _pack_length(len(d) + 1) + b"\x00" + d


def _asn1_object(d):
    return b"\x06" + _pack_length(len(d)) + d


def build_private_pkcs1(numbers):
    values = [
        _int_to_asn1_int(0),
        _int_to_asn1_int(numbers.public_numbers.n),
        _int_to_asn1_int(numbers.public_numbers.e),
        _int_to_asn1_int(numbers.d),
        _int_to_asn1_int(numbers.p),
        _int_to_asn1_int(numbers.q),
        _int_to_asn1_int(numbers.dmp1),
        _int_to_asn1_int(numbers.dmq1),
        _int_to_asn1_int(numbers.iqmp)
    ]
    return _asn1_seq(values)


def build_public_pkcs1(numbers):
    public_seq = _asn1_seq([
        _int_to_asn1_int(numbers.n),
        _int_to_asn1_int(numbers.e)
    ])
    oid_seq = _asn1_seq([
        _asn1_object(_RSA_OID),
        _ASN1_NULL
    ])
    values = [oid_seq, _asn1_bit_string(public_seq)]

    return _asn1_seq(values)
