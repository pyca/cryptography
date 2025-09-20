# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import dataclasses
import sys
import typing

import cryptography.hazmat.asn1 as asn1

U = typing.TypeVar("U")


# Utility decorator that adds dataclass behavior similar
# to `sequence`, except that it also adds an __eq__ method.
# We use it for the objects under test in order to easily
# compare them with their expected values.
def _comparable_dataclass(cls: typing.Type[U]) -> typing.Type[U]:
    if sys.version_info >= (3, 10):
        return dataclasses.dataclass(
            repr=False,
            eq=True,
            # `match_args` was added in Python 3.10 and defaults
            # to True
            match_args=False,
            # `kw_only` was added in Python 3.10 and defaults to
            # False
            kw_only=True,
        )(cls)
    else:
        return dataclasses.dataclass(
            repr=False,
            eq=True,
        )(cls)


def assert_roundtrips(
    test_cases: typing.List[typing.Tuple[typing.Any, bytes]],
) -> None:
    for obj, obj_bytes in test_cases:
        encoded = asn1.encode_der(obj)
        assert encoded == obj_bytes

        decoded = asn1.decode_der(type(obj), encoded)
        assert isinstance(decoded, type(obj))
        assert decoded == obj


class TestInteger:
    def test_int(self) -> None:
        assert_roundtrips(
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


class TestSequence:
    def test_ok_sequence_single_field(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: int

        assert_roundtrips([(Example(foo=9), b"\x30\x03\x02\x01\x09")])

    def test_encode_ok_sequence_multiple_fields(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: int
            bar: int

        assert_roundtrips(
            [(Example(foo=9, bar=6), b"\x30\x06\x02\x01\x09\x02\x01\x06")]
        )

    def test_encode_ok_nested_sequence(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Child:
            foo: int

        @asn1.sequence
        @_comparable_dataclass
        class Parent:
            foo: Child

        assert_roundtrips(
            [(Parent(foo=Child(foo=9)), b"\x30\x05\x30\x03\x02\x01\x09")]
        )
