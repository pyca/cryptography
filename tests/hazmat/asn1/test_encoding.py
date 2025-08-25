# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import pytest

import cryptography.hazmat.asn1 as asn1


class TestEncodeInteger:
    @pytest.mark.parametrize(
        "value,expected",
        [
            (0, b"\x02\x01\x00"),
            (1, b"\x02\x01\x01"),
            (42, b"\x02\x01\x2a"),
            (127, b"\x02\x01\x7f"),
            (128, b"\x02\x02\x00\x80"),
            (255, b"\x02\x02\x00\xff"),
            (256, b"\x02\x02\x01\x00"),
            (-1, b"\x02\x01\xff"),
            (-128, b"\x02\x01\x80"),
            (-129, b"\x02\x02\xff\x7f"),
        ],
    )
    def test_encode_int(self, value: int, expected: bytes) -> None:
        encoded = asn1.encode_der(value)
        assert encoded == expected, (
            f"Failed for {value}: got {encoded.hex()}, expected"
            f"{expected.hex()}"
        )


class TestEncodeSequence:
    def test_encode_ok_sequence_single_field(self) -> None:
        @asn1.sequence
        class Example:
            foo: int

        value = Example(foo=9)

        encoded = asn1.encode_der(value)
        assert encoded == b"\x30\x03\x02\x01\x09"

    def test_encode_ok_sequence_multiple_fields(self) -> None:
        @asn1.sequence
        class Example:
            foo: int
            bar: int

        value = Example(foo=9, bar=6)

        encoded = asn1.encode_der(value)
        assert encoded == b"\x30\x06\x02\x01\x09\x02\x01\x06"

    def test_encode_ok_nested_sequence(self) -> None:
        @asn1.sequence
        class Child:
            foo: int

        @asn1.sequence
        class Parent:
            foo: Child

        value = Parent(foo=Child(foo=9))

        encoded = asn1.encode_der(value)
        assert encoded == b"\x30\x05\x30\x03\x02\x01\x09"
