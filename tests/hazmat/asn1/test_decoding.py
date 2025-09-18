# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import pytest

import cryptography.hazmat.asn1 as asn1


class TestDecodeInteger:
    @pytest.mark.parametrize(
        "value,expected",
        [
            (b"\x02\x01\x00", 0),
            (b"\x02\x01\x01", 1),
            (b"\x02\x01\x2a", 42),
            (b"\x02\x01\x7f", 127),
            (b"\x02\x02\x00\x80", 128),
            (b"\x02\x02\x00\xff", 255),
            (b"\x02\x02\x01\x00", 256),
            (b"\x02\x01\xff", -1),
            (b"\x02\x01\x80", -128),
            (b"\x02\x02\xff\x7f", -129),
        ],
    )
    def test_decode_int(self, value: bytes, expected: int) -> None:
        decoded = asn1.decode_der(int, value)
        assert isinstance(decoded, int)
        assert decoded == expected, (
            f"Failed for {value.hex()}: got {decoded}, expected {expected}"
        )


class TestDecodeSequence:
    def test_decode_ok_sequence_single_field(self) -> None:
        @asn1.sequence
        class Example:
            foo: int

        decoded = asn1.decode_der(Example, b"\x30\x03\x02\x01\x09")

        assert decoded.foo == 9

    def test_decode_ok_sequence_multiple_fields(self) -> None:
        @asn1.sequence
        class Example:
            foo: int
            bar: int

        decoded = asn1.decode_der(Example, b"\x30\x06\x02\x01\x09\x02\x01\x06")

        assert decoded.foo == 9
        assert decoded.bar == 6

    def test_decode_ok_nested_sequence(self) -> None:
        @asn1.sequence
        class Child:
            foo: int

        @asn1.sequence
        class Parent:
            foo: Child

        decoded = asn1.decode_der(Parent, b"\x30\x05\x30\x03\x02\x01\x09")

        assert decoded.foo.foo == 9
