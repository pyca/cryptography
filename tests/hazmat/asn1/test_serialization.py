# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import dataclasses
import datetime
import re
import sys
import typing

import pytest

if sys.version_info < (3, 9):
    from typing_extensions import Annotated
else:
    from typing import Annotated

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


class TestIA5String:
    def test_ok_ia5_string(self) -> None:
        assert_roundtrips(
            [
                (asn1.IA5String(""), b"\x16\x00"),
                (asn1.IA5String("hello"), b"\x16\x05hello"),
                (asn1.IA5String("Test User 1"), b"\x16\x0bTest User 1"),
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
    def test_fail_generalized_time_precision(self) -> None:
        with pytest.raises(
            ValueError,
            match="decoded GeneralizedTime data has higher precision than "
            "supported",
        ):
            asn1.decode_der(
                asn1.GeneralizedTime, b"\x18\x1719990101000000.1234567Z"
            )

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


class TestBitString:
    def test_ok_bitstring(self) -> None:
        assert_roundtrips(
            [
                (
                    asn1.BitString(data=b"\x6e\x5d\xc0", padding_bits=6),
                    b"\x03\x04\x06\x6e\x5d\xc0",
                ),
                (
                    asn1.BitString(data=b"", padding_bits=0),
                    b"\x03\x01\x00",
                ),
                (
                    asn1.BitString(data=b"\x00", padding_bits=7),
                    b"\x03\x02\x07\x00",
                ),
                (
                    asn1.BitString(data=b"\x80", padding_bits=7),
                    b"\x03\x02\x07\x80",
                ),
                (
                    asn1.BitString(data=b"\x81\xf0", padding_bits=4),
                    b"\x03\x03\x04\x81\xf0",
                ),
            ]
        )

    def test_fail_bitstring(self) -> None:
        with pytest.raises(ValueError, match="error parsing asn1 value"):
            # Prefix with number of padding bits missing
            asn1.decode_der(asn1.BitString, b"\x03\x00")

        with pytest.raises(ValueError, match="error parsing asn1 value"):
            # Non-zero padding bits
            asn1.decode_der(asn1.BitString, b"\x03\x02\x07\x01")

        with pytest.raises(ValueError, match="error parsing asn1 value"):
            # Non-zero padding bits
            asn1.decode_der(asn1.BitString, b"\x03\x02\x07\x40")

        with pytest.raises(ValueError, match="error parsing asn1 value"):
            # Padding bits > 7
            asn1.decode_der(asn1.BitString, b"\x03\x02\x08\x00")


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

    def test_ok_sequenceof_simple_type(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: typing.List[int]

        assert_roundtrips(
            [
                (
                    Example(a=[1, 2, 3, 4]),
                    b"\x30\x0e\x30\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
                )
            ]
        )

    def test_ok_sequenceof_user_defined_type(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class MyType:
            a: int
            b: bool

        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: typing.List[MyType]

        assert_roundtrips(
            [
                (
                    Example(a=[MyType(a=1, b=True), MyType(a=2, b=False)]),
                    b"\x30\x12\x30\x10\x30\x06\x02\x01\x01\x01\x01\xff\x30\x06\x02\x01\x02\x01\x01\x00",
                )
            ]
        )

    def test_ok_sequenceof_size_restriction(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[typing.List[int], asn1.Size(min=1, max=4)]

        assert_roundtrips(
            [
                (
                    Example(a=[1, 2, 3, 4]),
                    b"\x30\x0e\x30\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
                )
            ]
        )

    def test_ok_sequenceof_size_restriction_no_max(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[typing.List[int], asn1.Size(min=1, max=None)]

        assert_roundtrips(
            [
                (
                    Example(a=[1, 2, 3, 4]),
                    b"\x30\x0e\x30\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
                )
            ]
        )

    def test_ok_sequenceof_size_restriction_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[typing.List[int], asn1.Size.exact(4)]

        assert_roundtrips(
            [
                (
                    Example(a=[1, 2, 3, 4]),
                    b"\x30\x0e\x30\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
                )
            ]
        )

    def test_fail_sequenceof_size_too_big(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[typing.List[int], asn1.Size(min=1, max=2)]

        with pytest.raises(
            ValueError,
            match=re.escape("SEQUENCE OF has size 4, expected size in [1, 2]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x0e\x30\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=[1, 2, 3, 4]))

    def test_fail_sequenceof_size_too_small(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[typing.List[int], asn1.Size(min=5, max=6)]

        with pytest.raises(
            ValueError,
            match=re.escape("SEQUENCE OF has size 4, expected size in [5, 6]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x0e\x30\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=[1, 2, 3, 4]))

    def test_fail_sequenceof_size_not_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[typing.List[int], asn1.Size.exact(5)]

        with pytest.raises(
            ValueError,
            match=re.escape("SEQUENCE OF has size 4, expected size in [5, 5]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x0e\x30\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=[1, 2, 3, 4]))

    def test_ok_sequence_with_optionals(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: typing.Union[bool, None]
            b: int
            c: bytes
            d: typing.Union[None, str]

        assert_roundtrips(
            [
                # All fields are present
                (
                    Example(a=True, b=9, c=b"c", d="d"),
                    b"\x30\x0c\x01\x01\xff\x02\x01\x09\x04\x01c\x0c\x01d",
                ),
                # All optional fields are missing
                (
                    Example(a=None, b=9, c=b"c", d=None),
                    b"\x30\x06\x02\x01\x09\x04\x01c",
                ),
                # Some optional fields are missing
                (
                    Example(a=True, b=9, c=b"c", d=None),
                    b"\x30\x09\x01\x01\xff\x02\x01\x09\x04\x01c",
                ),
            ]
        )

    def test_ok_sequence_with_nested_optionals(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: typing.Union[typing.Union[bool, None], None]
            b: int
            c: bytes
            d: typing.Union[None, typing.Union[None, str]]

        assert_roundtrips(
            [
                # All fields are present
                (
                    Example(a=True, b=9, c=b"c", d="d"),
                    b"\x30\x0c\x01\x01\xff\x02\x01\x09\x04\x01c\x0c\x01d",
                ),
                # All optional fields are missing
                (
                    Example(a=None, b=9, c=b"c", d=None),
                    b"\x30\x06\x02\x01\x09\x04\x01c",
                ),
                # Some optional fields are missing
                (
                    Example(a=True, b=9, c=b"c", d=None),
                    b"\x30\x09\x01\x01\xff\x02\x01\x09\x04\x01c",
                ),
            ]
        )

    def test_ok_sequence_all_types_optional(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class MyField:
            a: int

        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: typing.Union[MyField, None]
            b: typing.Union[int, None]
            c: typing.Union[bytes, None]
            d: typing.Union[asn1.PrintableString, None]
            e: typing.Union[asn1.UtcTime, None]
            f: typing.Union[asn1.GeneralizedTime, None]
            g: typing.Union[typing.List[int], None]
            h: typing.Union[asn1.BitString, None]
            i: typing.Union[asn1.IA5String, None]

        assert_roundtrips(
            [
                (
                    Example(
                        a=None,
                        b=None,
                        c=None,
                        d=None,
                        e=None,
                        f=None,
                        g=None,
                        h=None,
                        i=None,
                    ),
                    b"\x30\x00",
                )
            ]
        )

    def test_ok_sequence_with_default_annotations(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[bool, asn1.Default(True)]
            b: int
            c: bytes
            d: Annotated[str, asn1.Default("d")]

        assert_roundtrips(
            [
                # No DEFAULT fields contain their default value
                (
                    Example(a=False, b=9, c=b"c", d="x"),
                    b"\x30\x0c\x01\x01\x00\x02\x01\x09\x04\x01c\x0c\x01x",
                ),
                # All DEFAULT fields contain their default value
                (
                    Example(a=True, b=9, c=b"c", d="d"),
                    b"\x30\x06\x02\x01\x09\x04\x01c",
                ),
                # Some DEFAULT fields contain their default value
                (
                    Example(a=False, b=9, c=b"c", d="d"),
                    b"\x30\x09\x01\x01\x00\x02\x01\x09\x04\x01c",
                ),
            ]
        )

    def test_fail_decode_default_value_present(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[bool, asn1.Default(True)]

        with pytest.raises(
            ValueError,
            match="invalid DER: DEFAULT value was explicitly encoded",
        ):
            asn1.decode_der(Example, b"\x30\x03\x01\x01\xff")

    def test_ok_optional_fields_with_implicit_encoding(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[typing.Union[int, None], asn1.Implicit(0)]
            b: Annotated[typing.Union[int, None], asn1.Implicit(1)]

        assert_roundtrips(
            [
                (Example(a=9, b=9), b"\x30\x06\x80\x01\x09\x81\x01\x09"),
                (Example(a=9, b=None), b"\x30\x03\x80\x01\x09"),
                (Example(a=None, b=9), b"\x30\x03\x81\x01\x09"),
                (Example(a=None, b=None), b"\x30\x00"),
            ]
        )

    def test_ok_optional_fields_with_explicit_encoding(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[typing.Union[int, None], asn1.Explicit(0)]
            b: Annotated[typing.Union[int, None], asn1.Explicit(1)]

        assert_roundtrips(
            [
                (
                    Example(a=9, b=9),
                    b"\x30\x0a\xa0\x03\x02\x01\x09\xa1\x03\x02\x01\x09",
                ),
                (
                    Example(a=9, b=None),
                    b"\x30\x05\xa0\x03\x02\x01\x09",
                ),
                (
                    Example(a=None, b=9),
                    b"\x30\x05\xa1\x03\x02\x01\x09",
                ),
                (
                    Example(a=None, b=None),
                    b"\x30\x00",
                ),
            ]
        )

    def test_fail_unexpected_fields_with_implicit_encoding(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[int, asn1.Implicit(0)]

        with pytest.raises(
            ValueError,
            match=re.escape(
                "error parsing asn1 value: ParseError { kind: UnexpectedTag"
            ),
        ):
            asn1.decode_der(Example, b"\x30\x03\x82\x01\x09")

    def test_fail_unexpected_fields_with_explicit_encoding(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[int, asn1.Explicit(0)]

        with pytest.raises(
            ValueError,
            match=re.escape(
                "error parsing asn1 value: ParseError { kind: UnexpectedTag"
            ),
        ):
            asn1.decode_der(Example, b"\x30\x05\xa2\x03\x02\x01\x09")
