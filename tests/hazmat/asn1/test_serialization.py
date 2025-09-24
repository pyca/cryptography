# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import dataclasses
import sys
import typing

import pytest

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


# Checks that the encoding-decoding roundtrip results
# in the expected values and is consistent.
#
# The `decoded_eq` argument is the equality function to use
# for the decoded values. It's useful for types that aren't
# directly comparable, like `PrintableString`.
def assert_roundtrips(
    test_cases: typing.List[typing.Tuple[U, bytes]],
    decoded_eq: typing.Optional[typing.Callable[[U, U], bool]] = None,
) -> None:
    for obj, obj_bytes in test_cases:
        encoded = asn1.encode_der(obj)
        assert encoded == obj_bytes

        decoded = asn1.decode_der(type(obj), encoded)
        assert isinstance(decoded, type(obj))
        if decoded_eq:
            assert decoded_eq(decoded, obj)
        else:
            assert decoded == obj


class TestBool:
    def test_bool(self) -> None:
        assert_roundtrips(
            [
                (True, b"\x01\x01\xff"),
                (False, b"\x01\x01\x00"),
            ],
        )


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


class TestBytes:
    def test_bytes(self) -> None:
        assert_roundtrips(
            [
                (b"", b"\x04\x00"),
                (b"hello", b"\x04\x05hello"),
                (b"\x01\x02\x03", b"\x04\x03\x01\x02\x03"),
                (
                    b"\x00\xff\x80\x7f",
                    b"\x04\x04\x00\xff\x80\x7f",
                ),
            ]
        )


class TestString:
    def test_string(self) -> None:
        assert_roundtrips(
            [
                ("", b"\x0c\x00"),
                ("hello", b"\x0c\x05hello"),
                ("Test User 1", b"\x0c\x0bTest User 1"),
                (
                    "café",
                    b"\x0c\x05caf\xc3\xa9",
                ),  # UTF-8 string with non-ASCII
                ("🚀", b"\x0c\x04\xf0\x9f\x9a\x80"),  # UTF-8 emoji
            ]
        )


class TestPrintableString:
    def test_ok_printable_string(self) -> None:
        def decoded_eq(a: asn1.PrintableString, b: asn1.PrintableString):
            return a.as_str() == b.as_str()

        assert_roundtrips(
            [
                (asn1.PrintableString(""), b"\x13\x00"),
                (asn1.PrintableString("hello"), b"\x13\x05hello"),
                (asn1.PrintableString("Test User 1"), b"\x13\x0bTest User 1"),
            ],
            decoded_eq,
        )

    def test_invalid_printable_string(self) -> None:
        with pytest.raises(ValueError, match="allocation error"):
            asn1.encode_der(asn1.PrintableString("café"))

        with pytest.raises(ValueError, match="error parsing asn1 value"):
            asn1.decode_der(asn1.PrintableString, b"\x0c\x05caf\xc3\xa9")


class TestSequence:
    def test_ok_sequence_single_field(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: int

        assert_roundtrips([(Example(foo=9), b"\x30\x03\x02\x01\x09")])

    def test_ok_sequence_multiple_fields(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: int
            bar: int

        assert_roundtrips(
            [(Example(foo=9, bar=6), b"\x30\x06\x02\x01\x09\x02\x01\x06")]
        )

    def test_ok_nested_sequence(self) -> None:
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

    def test_ok_sequence_multiple_types(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: bool
            b: int
            c: bytes
            d: str

        assert_roundtrips(
            [
                (
                    Example(a=True, b=9, c=b"c", d="d"),
                    b"\x30\x0c\x01\x01\xff\x02\x01\x09\x04\x01c\x0c\x01d",
                )
            ]
        )
