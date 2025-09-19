# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

import pytest

import cryptography.hazmat.asn1 as asn1


def assert_roundtrip(obj: typing.Any, obj_bytes: bytes) -> None:
    encoded = asn1.encode_der(obj)
    assert encoded == obj_bytes, (
        f"Failed for {obj}: got {encoded.hex()}, expected{obj_bytes.hex()}"
    )

    decoded = asn1.decode_der(type(obj), encoded)
    assert isinstance(decoded, type(obj))
    assert decoded == obj


class TestInteger:
    @pytest.mark.parametrize(
        "obj,obj_bytes",
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
    def test_int(self, obj: int, obj_bytes: bytes) -> None:
        assert_roundtrip(obj, obj_bytes)


class TestSequence:
    def test_ok_sequence_single_field(self) -> None:
        @asn1.sequence
        class Example:
            foo: int

        assert_roundtrip(obj=Example(foo=9), obj_bytes=b"\x30\x03\x02\x01\x09")

    def test_encode_ok_sequence_multiple_fields(self) -> None:
        @asn1.sequence
        class Example:
            foo: int
            bar: int

        assert_roundtrip(
            obj=Example(foo=9, bar=6),
            obj_bytes=b"\x30\x06\x02\x01\x09\x02\x01\x06",
        )

    def test_encode_ok_nested_sequence(self) -> None:
        @asn1.sequence
        class Child:
            foo: int

        @asn1.sequence
        class Parent:
            foo: Child

        assert_roundtrip(
            obj=Parent(foo=Child(foo=9)),
            obj_bytes=b"\x30\x05\x30\x03\x02\x01\x09",
        )
