# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import dataclasses
import datetime
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


# Checks that the encoding-decoding roundtrip results
# in the expected values and is consistent.
def assert_roundtrips(
    test_cases: typing.List[typing.Tuple[U, bytes]],
) -> None:
    for obj, obj_bytes in test_cases:
        encoded = asn1.encode_der(obj)
        assert encoded == obj_bytes

        decoded = asn1.decode_der(type(obj), encoded)
        assert isinstance(decoded, type(obj))
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
        assert_roundtrips(
            [
                (asn1.PrintableString(""), b"\x13\x00"),
                (asn1.PrintableString("hello"), b"\x13\x05hello"),
                (asn1.PrintableString("Test User 1"), b"\x13\x0bTest User 1"),
            ]
        )


class TestUtcTime:
    def test_utc_time(self) -> None:
        assert_roundtrips(
            [
                (
                    asn1.UtcTime(
                        datetime.datetime(
                            2019,
                            12,
                            16,
                            3,
                            2,
                            10,
                            tzinfo=datetime.timezone.utc,
                        )
                    ),
                    b"\x17\x0d191216030210Z",
                ),
                (
                    asn1.UtcTime(
                        datetime.datetime(
                            1999,
                            1,
                            1,
                            0,
                            0,
                            0,
                            tzinfo=datetime.timezone.utc,
                        )
                    ),
                    b"\x17\x0d990101000000Z",
                ),
            ],
        )


class TestGeneralizedTime:
    def test_generalized_time(self) -> None:
        assert_roundtrips(
            [
                (
                    asn1.GeneralizedTime(
                        datetime.datetime(
                            2019,
                            12,
                            16,
                            3,
                            2,
                            10,
                            tzinfo=datetime.timezone.utc,
                        )
                    ),
                    b"\x18\x0f20191216030210Z",
                ),
                (
                    asn1.GeneralizedTime(
                        datetime.datetime(
                            1999,
                            1,
                            1,
                            0,
                            0,
                            0,
                            microsecond=500000,  # half a second
                            tzinfo=datetime.timezone.utc,
                        )
                    ),
                    b"\x18\x1119990101000000.5Z",
                ),
                (
                    asn1.GeneralizedTime(
                        datetime.datetime(
                            2050,
                            6,
                            15,
                            14,
                            22,
                            33,
                            tzinfo=datetime.timezone.utc,
                        )
                    ),
                    b"\x18\x0f20500615142233Z",
                ),
            ],
        )


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
