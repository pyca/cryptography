# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import dataclasses
import datetime
import enum
import os
import re
import sys
import typing
from typing import Annotated

import pytest

from cryptography import x509
from cryptography.hazmat import asn1
from cryptography.hazmat.primitives.serialization import Encoding

from ...utils import load_vectors_from_file

U = typing.TypeVar("U")


# Utility decorator that adds dataclass behavior similar
# to `sequence`, except that it also adds an __eq__ method.
# We use it for the objects under test in order to easily
# compare them with their expected values.
def _comparable_dataclass(cls: type[U]) -> type[U]:
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
    test_cases: list[tuple[U, bytes]],
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


class TestObjectIdentifier:
    def test_ok_object_identifier(self) -> None:
        assert_roundtrips(
            [
                (
                    x509.ObjectIdentifier("1.3.6.1.4.1.343"),
                    b"\x06\x07\x2b\x06\x01\x04\x01\x82\x57",
                ),
                (
                    x509.ObjectIdentifier("1.2.840.113549.1.1.1"),
                    b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01",
                ),
                (
                    x509.ObjectIdentifier("1.3.6.1.4.1.55738.3"),
                    b"\x06\x09\x2b\x06\x01\x04\x01\x83\xb3\x3a\x03",
                ),
            ]
        )


class TestUTCTime:
    def test_utc_time(self) -> None:
        assert_roundtrips(
            [
                (
                    asn1.UTCTime(
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
                    asn1.UTCTime(
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


class TestTLV:
    def test_ok_decode_tlv(self) -> None:
        decoded = asn1.decode_der(asn1.TLV, b"\x03\x02\x07\x40")
        assert isinstance(decoded, asn1.TLV)
        assert decoded.tag_bytes == b"\x03"
        assert bytes(decoded.data) == b"\x07\x40"

    def test_ok_tlv_parse_method(self) -> None:
        decoded_tlv = asn1.decode_der(asn1.TLV, b"\x30\x03\x02\x01\x09")
        assert isinstance(decoded_tlv, asn1.TLV)

        @asn1.sequence
        class Example:
            foo: int

        decoded_example = decoded_tlv.parse(Example)
        assert isinstance(decoded_example, Example)
        assert decoded_example.foo == 9

    def test_fail_encode_tlv(self) -> None:
        tlv = asn1.decode_der(asn1.TLV, b"\x03\x02\x07\x40")
        assert isinstance(tlv, asn1.TLV)

        with pytest.raises(
            NotImplementedError, match="TLV encoding currently not supported"
        ):
            asn1.encode_der(tlv)


class TestNull:
    def test_ok_null(self) -> None:
        assert_roundtrips([(asn1.Null(), b"\x05\x00")])


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
            a: list[int]

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
            a: list[MyType]

        assert_roundtrips(
            [
                (
                    Example(a=[MyType(a=1, b=True), MyType(a=2, b=False)]),
                    b"\x30\x12\x30\x10\x30\x06\x02\x01\x01\x01\x01\xff\x30\x06\x02\x01\x02\x01\x01\x00",
                )
            ]
        )

    def test_ok_setof_simple_type(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: asn1.SetOf[int]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.SetOf([1, 2, 3, 4])),
                    b"\x30\x0e\x31\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
                )
            ]
        )

    def test_ok_setof_user_defined_type(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class MyType:
            a: int
            b: bool

        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: asn1.SetOf[MyType]

        assert_roundtrips(
            [
                (
                    Example(
                        a=asn1.SetOf(
                            [MyType(a=1, b=True), MyType(a=2, b=False)]
                        )
                    ),
                    b"\x30\x12\x31\x10\x30\x06\x02\x01\x01\x01\x01\xff\x30\x06\x02\x01\x02\x01\x01\x00",
                )
            ]
        )

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

        @asn1.set
        @_comparable_dataclass
        class MySetField:
            a: int

        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: typing.Union[MyField, None]
            a2: typing.Union[MySetField, None]
            b: typing.Union[int, None]
            c: typing.Union[bytes, None]
            d: typing.Union[asn1.PrintableString, None]
            e: typing.Union[asn1.UTCTime, None]
            f: typing.Union[asn1.GeneralizedTime, None]
            g: typing.Union[list[int], None]
            g2: typing.Union[asn1.SetOf[int], None]
            h: typing.Union[asn1.BitString, None]
            i: typing.Union[asn1.IA5String, None]
            j: typing.Union[x509.ObjectIdentifier, None]
            k: typing.Union[asn1.Null, None]
            z: Annotated[typing.Union[str, None], asn1.Implicit(0)]
            only_field_present: Annotated[
                typing.Union[str, None], asn1.Implicit(1)
            ]

        assert_roundtrips(
            [
                (
                    Example(
                        a=None,
                        a2=None,
                        b=None,
                        c=None,
                        d=None,
                        e=None,
                        f=None,
                        g=None,
                        g2=None,
                        h=None,
                        i=None,
                        j=None,
                        k=None,
                        z=None,
                        only_field_present="a",
                    ),
                    b"\x30\x03\x81\x01a",
                )
            ]
        )

    def test_ok_sequence_all_types_default(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class MyField:
            a: int

        default_time = datetime.datetime(
            2019,
            12,
            16,
            3,
            2,
            10,
            tzinfo=datetime.timezone.utc,
        )
        default_oid = x509.ObjectIdentifier("1.3.6.1.4.1.343")

        @asn1.set
        @_comparable_dataclass
        class MySetField:
            a: int

        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[int, asn1.Default(3)]
            b: Annotated[bytes, asn1.Default(b"\x00")]
            c: Annotated[
                asn1.PrintableString, asn1.Default(asn1.PrintableString("a"))
            ]
            d: Annotated[
                asn1.UTCTime,
                asn1.Default(asn1.UTCTime(default_time)),
            ]
            e: Annotated[
                asn1.GeneralizedTime,
                asn1.Default(asn1.GeneralizedTime(default_time)),
            ]
            f: Annotated[list[int], asn1.Default([1])]
            g: Annotated[
                asn1.BitString,
                asn1.Default(
                    asn1.BitString(data=b"", padding_bits=0),
                ),
            ]
            h: Annotated[asn1.IA5String, asn1.Default(asn1.IA5String("a"))]
            i: Annotated[
                x509.ObjectIdentifier,
                asn1.Default(default_oid),
            ]
            j: Annotated[
                typing.Union[int, bool], asn1.Default(3), asn1.Explicit(0)
            ]
            k: Annotated[
                asn1.Null,
                asn1.Default(asn1.Null()),
            ]
            k2: Annotated[
                MyField,
                asn1.Default(MyField(a=9)),
            ]
            k3: Annotated[
                MySetField,
                asn1.Default(MySetField(a=9)),
            ]
            z: Annotated[str, asn1.Default("a"), asn1.Implicit(0)]
            only_field_present: Annotated[
                str, asn1.Default("a"), asn1.Implicit(1)
            ]

        assert_roundtrips(
            [
                (
                    Example(
                        a=3,
                        b=b"\x00",
                        c=asn1.PrintableString("a"),
                        d=asn1.UTCTime(default_time),
                        e=asn1.GeneralizedTime(default_time),
                        f=[1],
                        g=asn1.BitString(data=b"", padding_bits=0),
                        h=asn1.IA5String("a"),
                        i=default_oid,
                        j=3,
                        k=asn1.Null(),
                        k2=MyField(a=9),
                        k3=MySetField(a=9),
                        z="a",
                        only_field_present="b",
                    ),
                    b"\x30\x03\x81\x01b",
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

    def test_sequence_with_choice(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: typing.Union[int, bool, str]

        assert_roundtrips(
            [
                (Example(foo=9), b"\x30\x03\x02\x01\x09"),
                (Example(foo=True), b"\x30\x03\x01\x01\xff"),
                (Example(foo="a"), b"\x30\x03\x0c\x01a"),
            ]
        )

    def test_sequence_with_optional_choice(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: typing.Union[bool, str, None]
            bar: int

        assert_roundtrips(
            [
                (
                    Example(foo=True, bar=1),
                    b"\x30\x06\x01\x01\xff\x02\x01\x01",
                ),
                (Example(foo=None, bar=1), b"\x30\x03\x02\x01\x01"),
            ]
        )

    def test_fail_sequence_with_choice_decode_nonexistent_variant(
        self,
    ) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: typing.Union[bool, str]

        with pytest.raises(
            ValueError,
            match=re.escape(
                "could not find matching variant when parsing CHOICE field"
            ),
        ):
            asn1.decode_der(Example, b"\x30\x03\x02\x01\x09")

    def test_fail_sequence_with_choice_encode_nonexistent_variant(
        self,
    ) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: typing.Union[bool, str]

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(foo=3))  # type: ignore[arg-type]

    def test_sequence_with_explicit_choice(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: Annotated[typing.Union[int, bool, str], asn1.Explicit(3)]

        assert_roundtrips(
            [
                (Example(foo=9), b"\x30\x05\xa3\x03\x02\x01\x09"),
                (Example(foo=True), b"\x30\x05\xa3\x03\x01\x01\xff"),
                (Example(foo="a"), b"\x30\x05\xa3\x03\x0c\x01a"),
            ]
        )

    def test_sequence_with_choice_implicit_simple_variants(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: typing.Union[
                Annotated[int, asn1.Implicit(0)],
                Annotated[bool, asn1.Implicit(1)],
                Annotated[str, asn1.Implicit(2)],
            ]

        assert_roundtrips(
            [
                (Example(foo=9), b"\x30\x03\x80\x01\x09"),
                (Example(foo=True), b"\x30\x03\x81\x01\xff"),
                (Example(foo="a"), b"\x30\x03\x82\x01a"),
            ]
        )

    def test_sequence_with_choice_explicit_simple_variants(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: typing.Union[
                Annotated[int, asn1.Explicit(0)],
                Annotated[bool, asn1.Explicit(1)],
                Annotated[str, asn1.Explicit(2)],
            ]

        assert_roundtrips(
            [
                (Example(foo=9), b"\x30\x05\xa0\x03\x02\x01\x09"),
                (Example(foo=True), b"\x30\x05\xa1\x03\x01\x01\xff"),
                (Example(foo="a"), b"\x30\x05\xa2\x03\x0c\x01a"),
            ]
        )

    def test_sequence_with_choice_with_custom_variants(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: typing.Union[
                Annotated[
                    asn1.Variant[int, typing.Literal["IntA"]], asn1.Implicit(0)
                ],
                Annotated[
                    asn1.Variant[int, typing.Literal["IntB"]], asn1.Implicit(1)
                ],
                Annotated[
                    asn1.Variant[int, typing.Literal["IntC"]], asn1.Implicit(2)
                ],
            ]

        assert_roundtrips(
            [
                (
                    Example(foo=asn1.Variant(9, "IntA")),
                    b"\x30\x03\x80\x01\x09",
                ),
                (
                    Example(foo=asn1.Variant(9, "IntB")),
                    b"\x30\x03\x81\x01\x09",
                ),
                (
                    Example(foo=asn1.Variant(9, "IntC")),
                    b"\x30\x03\x82\x01\x09",
                ),
            ]
        )

    def test_sequence_with_choice_with_custom_variants_bool(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: typing.Union[
                Annotated[
                    asn1.Variant[bool, typing.Literal["BoolA"]],
                    asn1.Implicit(0),
                ],
                Annotated[
                    asn1.Variant[bool, typing.Literal["BoolB"]],
                    asn1.Implicit(1),
                ],
                Annotated[
                    asn1.Variant[bool, typing.Literal["BoolC"]],
                    asn1.Implicit(2),
                ],
            ]

        assert_roundtrips(
            [
                (
                    Example(foo=asn1.Variant(True, "BoolA")),
                    b"\x30\x03\x80\x01\xff",
                ),
                (
                    Example(foo=asn1.Variant(True, "BoolB")),
                    b"\x30\x03\x81\x01\xff",
                ),
                (
                    Example(foo=asn1.Variant(True, "BoolC")),
                    b"\x30\x03\x82\x01\xff",
                ),
            ]
        )

    def test_sequence_with_choice_with_sequence_variants(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: int

        @asn1.sequence
        @_comparable_dataclass
        class ExampleUnion:
            field: typing.Union[
                Annotated[
                    asn1.Variant[Example, typing.Literal["ExampleA"]],
                    asn1.Implicit(0),
                ],
                Annotated[
                    asn1.Variant[Example, typing.Literal["ExampleB"]],
                    asn1.Implicit(1),
                ],
            ]

        assert_roundtrips(
            [
                (
                    ExampleUnion(
                        field=asn1.Variant(Example(foo=9), "ExampleA")
                    ),
                    b"\x30\x05\xa0\x03\x02\x01\x09",
                ),
                (
                    ExampleUnion(
                        field=asn1.Variant(Example(foo=9), "ExampleB")
                    ),
                    b"\x30\x05\xa1\x03\x02\x01\x09",
                ),
            ]
        )

    def test_sequence_with_choice_with_non_annotated_custom_variants(
        self,
    ) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            foo: typing.Union[
                asn1.Variant[int, typing.Literal["MyInt"]],
                asn1.Variant[bool, typing.Literal["MyBool"]],
            ]

        assert_roundtrips(
            [
                (
                    Example(foo=asn1.Variant(9, "MyInt")),
                    b"\x30\x03\x02\x01\x09",
                ),
                (
                    Example(foo=asn1.Variant(True, "MyBool")),
                    b"\x30\x03\x01\x01\xff",
                ),
            ]
        )

    def test_sequence_with_tlv_with_explicit_annotation(
        self,
    ) -> None:
        @asn1.sequence
        class Example:
            foo: Annotated[asn1.TLV, asn1.Explicit(0)]
            bar: Annotated[asn1.TLV, asn1.Explicit(1)]

        encoded = b"\x30\x0a\xa0\x03\x02\x01\x08\xa1\x03\x02\x01\x09"
        decoded = asn1.decode_der(Example, encoded)

        assert isinstance(decoded.foo, asn1.TLV)
        assert decoded.foo.tag_bytes == b"\x02"
        assert bytes(decoded.foo.data) == b"\x08"

        assert isinstance(decoded.bar, asn1.TLV)
        assert decoded.bar.tag_bytes == b"\x02"
        assert bytes(decoded.bar.data) == b"\x09"

    def test_fail_sequence_with_tlv_with_explicit_annotation(
        self,
    ) -> None:
        @asn1.sequence
        class Example:
            foo: Annotated[asn1.TLV, asn1.Explicit(0)]
            # explicit tag does not match data
            bar: Annotated[asn1.TLV, asn1.Explicit(3)]

        with pytest.raises(
            ValueError,
            match=re.escape("error parsing asn1 value"),
        ):
            asn1.decode_der(
                Example, b"\x30\x0a\xa0\x03\x02\x01\x08\xa1\x03\x02\x01\x09"
            )


class TestSet:
    def test_ok_set_single_field(self) -> None:
        @asn1.set
        @_comparable_dataclass
        class Example:
            foo: int

        assert_roundtrips([(Example(foo=9), b"\x31\x03\x02\x01\x09")])

    def test_ok_set_multiple_fields(self) -> None:
        @asn1.set
        @_comparable_dataclass
        class Example:
            foo: int
            bar: int

        assert_roundtrips(
            [(Example(foo=6, bar=9), b"\x31\x06\x02\x01\x06\x02\x01\x09")]
        )

    def test_fail_set_multiple_fields_wrong_order(self) -> None:
        @asn1.set
        @_comparable_dataclass
        class Example:
            foo: int
            bar: int

        with pytest.raises(
            ValueError,
            match=re.escape(
                "invalid SET ordering while performing ASN.1 serialization"
            ),
        ):
            assert_roundtrips(
                [(Example(foo=9, bar=6), b"\x31\x06\x02\x01\x06\x02\x01\x09")]
            )

    def test_ok_nested_set(self) -> None:
        @asn1.set
        @_comparable_dataclass
        class Child:
            foo: int

        @asn1.set
        @_comparable_dataclass
        class Parent:
            foo: Child

        assert_roundtrips(
            [(Parent(foo=Child(foo=9)), b"\x31\x05\x31\x03\x02\x01\x09")]
        )

    def test_ok_set_multiple_types(self) -> None:
        @asn1.set
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
                    b"\x31\x0c\x01\x01\xff\x02\x01\x09\x04\x01c\x0c\x01d",
                )
            ]
        )


class TestSize:
    def test_ok_sequenceof_size_restriction(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[list[int], asn1.Size(min=1, max=4)]

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
            a: Annotated[list[int], asn1.Size(min=1, max=None)]

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
            a: Annotated[list[int], asn1.Size.exact(4)]

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
            a: Annotated[list[int], asn1.Size(min=1, max=2)]

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
            a: Annotated[list[int], asn1.Size(min=5, max=6)]

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
            a: Annotated[list[int], asn1.Size.exact(5)]

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

    def test_ok_setof_size_restriction(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.SetOf[int], asn1.Size(min=1, max=4)]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.SetOf([1, 2, 3, 4])),
                    b"\x30\x0e\x31\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
                )
            ]
        )

    def test_ok_setof_size_restriction_no_max(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.SetOf[int], asn1.Size(min=1, max=None)]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.SetOf([1, 2, 3, 4])),
                    b"\x30\x0e\x31\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
                )
            ]
        )

    def test_ok_setof_size_restriction_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.SetOf[int], asn1.Size.exact(4)]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.SetOf([1, 2, 3, 4])),
                    b"\x30\x0e\x31\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
                )
            ]
        )

    def test_fail_setof_size_too_big(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.SetOf[int], asn1.Size(min=1, max=2)]

        with pytest.raises(
            ValueError,
            match=re.escape("SET OF has size 4, expected size in [1, 2]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x0e\x31\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=asn1.SetOf([1, 2, 3, 4])))

    def test_fail_setof_size_too_small(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.SetOf[int], asn1.Size(min=5, max=6)]

        with pytest.raises(
            ValueError,
            match=re.escape("SET OF has size 4, expected size in [5, 6]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x0e\x31\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=asn1.SetOf([1, 2, 3, 4])))

    def test_fail_setof_size_not_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.SetOf[int], asn1.Size.exact(5)]

        with pytest.raises(
            ValueError,
            match=re.escape("SET OF has size 4, expected size in [5, 5]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x0e\x31\x0c\x02\x01\x01\x02\x01\x02\x02\x01\x03\x02\x01\x04",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=asn1.SetOf([1, 2, 3, 4])))

    def test_ok_bytes_size_restriction(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[bytes, asn1.Size(min=1, max=4)]

        assert_roundtrips(
            [
                (
                    Example(a=b"\x01\x02\x03\x04"),
                    b"\x30\x06\x04\x04\x01\x02\x03\x04",
                )
            ]
        )

    def test_ok_bytes_size_restriction_no_max(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[bytes, asn1.Size(min=1, max=None)]

        assert_roundtrips(
            [
                (
                    Example(a=b"\x01\x02\x03\x04"),
                    b"\x30\x06\x04\x04\x01\x02\x03\x04",
                )
            ]
        )

    def test_ok_bytes_size_restriction_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[bytes, asn1.Size.exact(4)]

        assert_roundtrips(
            [
                (
                    Example(a=b"\x01\x02\x03\x04"),
                    b"\x30\x06\x04\x04\x01\x02\x03\x04",
                )
            ]
        )

    def test_fail_bytes_size_too_big(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[bytes, asn1.Size(min=1, max=2)]

        with pytest.raises(
            ValueError,
            match=re.escape(
                "OCTET STRING has size 4, expected size in [1, 2]"
            ),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x06\x04\x04\x01\x02\x03\x04",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=b"\x01\x02\x03\x04"))

    def test_fail_bytes_size_too_small(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[bytes, asn1.Size(min=5, max=6)]

        with pytest.raises(
            ValueError,
            match=re.escape(
                "OCTET STRING has size 4, expected size in [5, 6]"
            ),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x06\x04\x04\x01\x02\x03\x04",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=b"\x01\x02\x03\x04"))

    def test_fail_bytes_size_not_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[bytes, asn1.Size.exact(5)]

        with pytest.raises(
            ValueError,
            match=re.escape(
                "OCTET STRING has size 4, expected size in [5, 5]"
            ),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x06\x04\x04\x01\x02\x03\x04",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=b"\x01\x02\x03\x04"))

    def test_ok_string_size_restriction(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[str, asn1.Size(min=1, max=4)]

        assert_roundtrips(
            [
                (
                    Example(a="abcd"),
                    b"\x30\x06\x0c\x04abcd",
                )
            ]
        )

    def test_ok_string_size_counts_characters(self) -> None:
        # "é€" is two characters but five UTF-8 bytes, so a SIZE constraint
        # measured in characters must accept it under max=2.
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[str, asn1.Size(min=1, max=2)]

        assert_roundtrips(
            [
                (
                    Example(a="é€"),
                    b"\x30\x07\x0c\x05\xc3\xa9\xe2\x82\xac",
                )
            ]
        )

    def test_fail_string_size_counts_characters(self) -> None:
        # "é€" is two characters; SIZE(min=3) must reject it even though it
        # is five UTF-8 bytes.
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[str, asn1.Size(min=3, max=10)]

        with pytest.raises(
            ValueError,
            match=re.escape("UTF8String has size 2, expected size in [3, 10]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x07\x0c\x05\xc3\xa9\xe2\x82\xac",
            )

    def test_ok_string_size_restriction_no_max(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[str, asn1.Size(min=1, max=None)]

        assert_roundtrips(
            [
                (
                    Example(a="abcd"),
                    b"\x30\x06\x0c\x04abcd",
                )
            ]
        )

    def test_ok_string_size_restriction_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[str, asn1.Size.exact(4)]

        assert_roundtrips(
            [
                (
                    Example(a="abcd"),
                    b"\x30\x06\x0c\x04abcd",
                )
            ]
        )

    def test_fail_string_size_too_big(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[str, asn1.Size(min=1, max=2)]

        with pytest.raises(
            ValueError,
            match=re.escape("UTF8String has size 4, expected size in [1, 2]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x06\x0c\x04abcd",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a="abcd"))

    def test_fail_string_size_too_small(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[str, asn1.Size(min=5, max=6)]

        with pytest.raises(
            ValueError,
            match=re.escape("UTF8String has size 4, expected size in [5, 6]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x06\x0c\x04abcd",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a="abcd"))

    def test_fail_string_size_not_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[str, asn1.Size.exact(5)]

        with pytest.raises(
            ValueError,
            match=re.escape("UTF8String has size 4, expected size in [5, 5]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x06\x0c\x04abcd",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a="abcd"))

    def test_ok_bitstring_size_restriction(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.BitString, asn1.Size(min=1, max=4)]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.BitString(data=b"\xf0", padding_bits=4)),
                    b"\x30\x04\x03\x02\x04\xf0",
                )
            ]
        )

    def test_ok_printablestring_size_restriction(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.PrintableString, asn1.Size(min=1, max=4)]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.PrintableString("abcd")),
                    b"\x30\x06\x13\x04abcd",
                )
            ]
        )

    def test_ok_printablestring_size_restriction_no_max(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.PrintableString, asn1.Size(min=1, max=None)]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.PrintableString("abcd")),
                    b"\x30\x06\x13\x04abcd",
                )
            ]
        )

    def test_ok_printablestring_size_restriction_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.PrintableString, asn1.Size.exact(4)]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.PrintableString("abcd")),
                    b"\x30\x06\x13\x04abcd",
                )
            ]
        )

    def test_fail_printablestring_size_too_big(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.PrintableString, asn1.Size(min=1, max=2)]

        with pytest.raises(
            ValueError,
            match=re.escape(
                "PrintableString has size 4, expected size in [1, 2]"
            ),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x06\x13\x04abcd",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=asn1.PrintableString("abcd")))

    def test_fail_printablestring_size_too_small(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.PrintableString, asn1.Size(min=5, max=6)]

        with pytest.raises(
            ValueError,
            match=re.escape(
                "PrintableString has size 4, expected size in [5, 6]"
            ),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x06\x13\x04abcd",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=asn1.PrintableString("abcd")))

    def test_fail_printablestring_size_not_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.PrintableString, asn1.Size.exact(5)]

        with pytest.raises(
            ValueError,
            match=re.escape(
                "PrintableString has size 4, expected size in [5, 5]"
            ),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x06\x13\x04abcd",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=asn1.PrintableString("abcd")))

    def test_ok_ia5string_size_restriction(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.IA5String, asn1.Size(min=1, max=4)]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.IA5String("abcd")),
                    b"\x30\x06\x16\x04abcd",
                )
            ]
        )

    def test_ok_ia5string_size_restriction_no_max(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.IA5String, asn1.Size(min=1, max=None)]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.IA5String("abcd")),
                    b"\x30\x06\x16\x04abcd",
                )
            ]
        )

    def test_ok_ia5string_size_restriction_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.IA5String, asn1.Size.exact(4)]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.IA5String("abcd")),
                    b"\x30\x06\x16\x04abcd",
                )
            ]
        )

    def test_fail_ia5string_size_too_big(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.IA5String, asn1.Size(min=1, max=2)]

        with pytest.raises(
            ValueError,
            match=re.escape("IA5String has size 4, expected size in [1, 2]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x06\x16\x04abcd",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=asn1.IA5String("abcd")))

    def test_fail_ia5string_size_too_small(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.IA5String, asn1.Size(min=5, max=6)]

        with pytest.raises(
            ValueError,
            match=re.escape("IA5String has size 4, expected size in [5, 6]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x06\x16\x04abcd",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=asn1.IA5String("abcd")))

    def test_fail_ia5string_size_not_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.IA5String, asn1.Size.exact(5)]

        with pytest.raises(
            ValueError,
            match=re.escape("IA5String has size 4, expected size in [5, 5]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x06\x16\x04abcd",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(Example(a=asn1.IA5String("abcd")))

    def test_ok_bitstring_size_restriction_no_max(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.BitString, asn1.Size(min=1, max=None)]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.BitString(data=b"\xf0", padding_bits=4)),
                    b"\x30\x04\x03\x02\x04\xf0",
                )
            ]
        )

    def test_ok_bitstring_size_restriction_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.BitString, asn1.Size.exact(4)]

        assert_roundtrips(
            [
                (
                    Example(a=asn1.BitString(data=b"\xf0", padding_bits=4)),
                    b"\x30\x04\x03\x02\x04\xf0",
                )
            ]
        )

    def test_fail_bitstring_size_too_big(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.BitString, asn1.Size(min=1, max=2)]

        with pytest.raises(
            ValueError,
            match=re.escape("BIT STRING has size 4, expected size in [1, 2]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x04\x03\x02\x04\xf0",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(
                Example(a=asn1.BitString(data=b"\xf0", padding_bits=4))
            )

    def test_fail_bitstring_size_too_small(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.BitString, asn1.Size(min=5, max=6)]

        with pytest.raises(
            ValueError,
            match=re.escape("BIT STRING has size 4, expected size in [5, 6]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x04\x03\x02\x04\xf0",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(
                Example(a=asn1.BitString(data=b"\xf0", padding_bits=4))
            )

    def test_fail_bitstring_size_not_exact(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            a: Annotated[asn1.BitString, asn1.Size.exact(5)]

        with pytest.raises(
            ValueError,
            match=re.escape("BIT STRING has size 4, expected size in [5, 5]"),
        ):
            asn1.decode_der(
                Example,
                b"\x30\x04\x03\x02\x04\xf0",
            )

        with pytest.raises(
            ValueError,
        ):
            asn1.encode_der(
                Example(a=asn1.BitString(data=b"\xf0", padding_bits=4))
            )


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    length_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(length_bytes)]) + length_bytes


class TestX509Types:
    @pytest.fixture
    def cert(self) -> x509.Certificate:
        return load_vectors_from_file(
            filename=os.path.join("x509", "custom", "post2000utctime.pem"),
            loader=lambda f: x509.load_pem_x509_certificate(f.read()),
            mode="rb",
        )

    @pytest.fixture
    def csr(self) -> x509.CertificateSigningRequest:
        return load_vectors_from_file(
            filename=os.path.join("x509", "requests", "rsa_sha1.pem"),
            loader=lambda f: x509.load_pem_x509_csr(f.read()),
            mode="rb",
        )

    @pytest.fixture
    def crl(self) -> x509.CertificateRevocationList:
        return load_vectors_from_file(
            filename=os.path.join("x509", "custom", "crl_all_reasons.pem"),
            loader=lambda f: x509.load_pem_x509_crl(f.read()),
            mode="rb",
        )

    def test_certificate(self, cert: x509.Certificate) -> None:
        assert_roundtrips([(cert, cert.public_bytes(Encoding.DER))])

    def test_csr(self, csr: x509.CertificateSigningRequest) -> None:
        assert_roundtrips([(csr, csr.public_bytes(Encoding.DER))])

    def test_crl(self, crl: x509.CertificateRevocationList) -> None:
        assert_roundtrips([(crl, crl.public_bytes(Encoding.DER))])

    def test_fields(
        self,
        cert: x509.Certificate,
        csr: x509.CertificateSigningRequest,
        crl: x509.CertificateRevocationList,
    ) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            cert: x509.Certificate
            csr: x509.CertificateSigningRequest
            crl: x509.CertificateRevocationList

        inner = (
            cert.public_bytes(Encoding.DER)
            + csr.public_bytes(Encoding.DER)
            + crl.public_bytes(Encoding.DER)
        )
        expected = b"\x30" + _der_length(len(inner)) + inner
        assert_roundtrips([(Example(cert=cert, csr=csr, crl=crl), expected)])

    def test_certificate_explicit(self, cert: x509.Certificate) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            cert: Annotated[x509.Certificate, asn1.Explicit(0)]

        cert_der = cert.public_bytes(Encoding.DER)
        inner = b"\xa0" + _der_length(len(cert_der)) + cert_der
        expected = b"\x30" + _der_length(len(inner)) + inner
        assert_roundtrips([(Example(cert=cert), expected)])

    def test_fail_certificate_implicit(self) -> None:
        with pytest.raises(
            TypeError,
            match=re.escape(
                "IMPLICIT annotations are not supported for X.509 types"
            ),
        ):

            @asn1.sequence
            class Example:
                cert: Annotated[x509.Certificate, asn1.Implicit(0)]

    def test_fail_optional_certificate_implicit(self) -> None:
        with pytest.raises(
            TypeError,
            match=re.escape(
                "IMPLICIT annotations are not supported for X.509 types"
            ),
        ):

            @asn1.sequence
            class Example:
                cert: Annotated[
                    typing.Union[x509.Certificate, None], asn1.Implicit(0)
                ]

    def test_optional_certificate(self, cert: x509.Certificate) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            cert: typing.Union[x509.Certificate, None]

        cert_der = cert.public_bytes(Encoding.DER)
        assert_roundtrips(
            [
                (
                    Example(cert=cert),
                    b"\x30" + _der_length(len(cert_der)) + cert_der,
                ),
                (Example(cert=None), b"\x30\x00"),
            ]
        )

    def test_certificate_choice(self, cert: x509.Certificate) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            field: typing.Union[x509.Certificate, int]

        cert_der = cert.public_bytes(Encoding.DER)
        assert_roundtrips(
            [
                (
                    Example(field=cert),
                    b"\x30" + _der_length(len(cert_der)) + cert_der,
                ),
                (
                    Example(field=9),
                    b"\x30" + _der_length(3) + b"\x02\x01\x09",
                ),
            ]
        )

    def test_decode_invalid(self) -> None:
        # Not even a valid TLV
        with pytest.raises(ValueError):
            asn1.decode_der(x509.Certificate, b"")

        # Wrong tag (INTEGER instead of SEQUENCE)
        with pytest.raises(ValueError):
            asn1.decode_der(x509.Certificate, b"\x02\x01\x00")

        # Valid SEQUENCEs, but not valid certificates/CSRs/CRLs
        with pytest.raises(ValueError):
            asn1.decode_der(x509.Certificate, b"\x30\x03\x02\x01\x00")
        with pytest.raises(ValueError):
            asn1.decode_der(
                x509.CertificateSigningRequest, b"\x30\x03\x02\x01\x00"
            )
        with pytest.raises(ValueError):
            asn1.decode_der(
                x509.CertificateRevocationList, b"\x30\x03\x02\x01\x00"
            )

    def test_encode_wrong_type(self) -> None:
        @asn1.sequence
        class Example:
            cert: x509.Certificate

        with pytest.raises(TypeError):
            asn1.encode_der(Example(cert=9))  # type: ignore[arg-type]


@asn1.value_set(x509.ObjectIdentifier)
class Algorithm(enum.Enum):
    A = x509.ObjectIdentifier("1.2.3.4")
    B = x509.ObjectIdentifier("1.2.3.5")


class TestValueSet:
    def test_ok_oid_value_set(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            algorithm: Algorithm

        assert_roundtrips(
            [
                (
                    Example(algorithm=Algorithm.A),
                    b"\x30\x05\x06\x03\x2a\x03\x04",
                ),
                (
                    Example(algorithm=Algorithm.B),
                    b"\x30\x05\x06\x03\x2a\x03\x05",
                ),
            ]
        )

        # Decoding returns the enum member itself
        decoded = asn1.decode_der(Example, b"\x30\x05\x06\x03\x2a\x03\x04")
        assert decoded.algorithm is Algorithm.A

    def test_ok_int_value_set(self) -> None:
        @asn1.value_set(int)
        class Version(enum.Enum):
            V1 = 1
            V2 = 2

        @asn1.sequence
        @_comparable_dataclass
        class Example:
            version: Version

        assert_roundtrips(
            [
                (Example(version=Version.V1), b"\x30\x03\x02\x01\x01"),
                (Example(version=Version.V2), b"\x30\x03\x02\x01\x02"),
            ]
        )

    def test_ok_top_level_value_set(self) -> None:
        assert_roundtrips(
            [
                (Algorithm.A, b"\x06\x03\x2a\x03\x04"),
                (Algorithm.B, b"\x06\x03\x2a\x03\x05"),
            ]
        )

    def test_ok_value_set_implicit(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            algorithm: Annotated[Algorithm, asn1.Implicit(0)]

        assert_roundtrips(
            [
                (
                    Example(algorithm=Algorithm.A),
                    b"\x30\x05\x80\x03\x2a\x03\x04",
                ),
            ]
        )

    def test_ok_value_set_explicit(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            algorithm: Annotated[Algorithm, asn1.Explicit(0)]

        assert_roundtrips(
            [
                (
                    Example(algorithm=Algorithm.A),
                    b"\x30\x07\xa0\x05\x06\x03\x2a\x03\x04",
                ),
            ]
        )

    def test_ok_optional_value_set(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            algorithm: typing.Union[Algorithm, None]

        assert_roundtrips(
            [
                (
                    Example(algorithm=Algorithm.A),
                    b"\x30\x05\x06\x03\x2a\x03\x04",
                ),
                (Example(algorithm=None), b"\x30\x00"),
            ]
        )

    def test_ok_value_set_default(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            algorithm: Annotated[Algorithm, asn1.Default(Algorithm.A)]

        assert_roundtrips(
            [
                (Example(algorithm=Algorithm.A), b"\x30\x00"),
                (
                    Example(algorithm=Algorithm.B),
                    b"\x30\x05\x06\x03\x2a\x03\x05",
                ),
            ]
        )

        with pytest.raises(
            ValueError, match="DEFAULT value was explicitly encoded"
        ):
            asn1.decode_der(Example, b"\x30\x05\x06\x03\x2a\x03\x04")

    def test_ok_value_set_in_choice(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            field: typing.Union[Algorithm, int]

        assert_roundtrips(
            [
                (
                    Example(field=Algorithm.A),
                    b"\x30\x05\x06\x03\x2a\x03\x04",
                ),
                (Example(field=9), b"\x30\x03\x02\x01\x09"),
            ]
        )

    def test_ok_null_value_set(self) -> None:
        # `Null` implements `__eq__` but not `__hash__`, so decoding
        # exercises the linear scan fallback (instead of the value ->
        # member map lookup).
        @asn1.value_set(asn1.Null)
        class Marker(enum.Enum):
            PRESENT = asn1.Null()

        assert_roundtrips(
            [
                (Marker.PRESENT, b"\x05\x00"),
            ]
        )

    def test_fail_decode_non_member_value(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            algorithm: Algorithm

        with pytest.raises(
            ValueError, match="is not a valid value for Algorithm"
        ):
            asn1.decode_der(Example, b"\x30\x05\x06\x03\x2a\x03\x06")

    def test_fail_decode_wrong_type(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            algorithm: Algorithm

        with pytest.raises(ValueError):
            asn1.decode_der(Example, b"\x30\x03\x02\x01\x01")

    def test_fail_encode_non_member(self) -> None:
        @asn1.sequence
        @_comparable_dataclass
        class Example:
            algorithm: Algorithm

        with pytest.raises(
            TypeError,
            match="value set field must be an instance of Algorithm, "
            "got: ObjectIdentifier",
        ):
            asn1.encode_der(
                Example(algorithm=x509.ObjectIdentifier("1.2.3.4"))  # type: ignore[arg-type]
            )
