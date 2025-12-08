# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

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


class TestTypesAPI:
    def test_repr_printable_string(self) -> None:
        my_string = "MyString"
        assert (
            repr(asn1.PrintableString(my_string))
            == f"PrintableString({my_string!r})"
        )

    def test_printable_string_as_str(self) -> None:
        my_string = "MyString"
        assert asn1.PrintableString(my_string).as_str() == my_string

    def test_invalid_printable_string(self) -> None:
        with pytest.raises(ValueError, match="invalid PrintableString: café"):
            asn1.PrintableString("café")

    def test_repr_ia5_string(self) -> None:
        my_string = "MyString"
        assert repr(asn1.IA5String(my_string)) == f"IA5String({my_string!r})"

    def test_ia5_string_as_str(self) -> None:
        my_string = "MyString"
        assert asn1.IA5String(my_string).as_str() == my_string

    def test_invalid_ia5_string(self) -> None:
        with pytest.raises(ValueError, match="invalid IA5String: café"):
            asn1.IA5String("café")

    def test_utc_time_as_datetime(self) -> None:
        dt = datetime.datetime(
            2000, 1, 1, 10, 10, 10, tzinfo=datetime.timezone.utc
        )
        assert asn1.UtcTime(dt).as_datetime() == dt

    def test_repr_utc_time(self) -> None:
        dt = datetime.datetime(
            2000, 1, 1, 10, 10, 10, tzinfo=datetime.timezone.utc
        )
        assert repr(asn1.UtcTime(dt)) == f"UtcTime({dt!r})"

    def test_invalid_utc_time(self) -> None:
        with pytest.raises(
            ValueError,
            match="cannot initialize with naive datetime object",
        ):
            # We don't allow naive datetime objects
            asn1.UtcTime(datetime.datetime(2000, 1, 1, 10, 10, 10))

        with pytest.raises(ValueError, match="invalid UtcTime"):
            # UtcTime does not support dates before 1950
            asn1.UtcTime(
                datetime.datetime(
                    1940, 1, 1, 10, 10, 10, tzinfo=datetime.timezone.utc
                )
            )

        with pytest.raises(ValueError, match="invalid UtcTime"):
            # UtcTime does not support dates after 2050
            asn1.UtcTime(
                datetime.datetime(
                    2090, 1, 1, 10, 10, 10, tzinfo=datetime.timezone.utc
                )
            )

        with pytest.raises(
            ValueError,
            match="invalid UtcTime: fractional seconds are not supported",
        ):
            # UtcTime does not support fractional seconds
            asn1.UtcTime(
                datetime.datetime(
                    2020,
                    1,
                    1,
                    10,
                    10,
                    10,
                    500000,
                    tzinfo=datetime.timezone.utc,
                )
            )

    def test_generalized_time_as_datetime(self) -> None:
        dt = datetime.datetime(
            2000, 1, 1, 10, 10, 10, 300000, tzinfo=datetime.timezone.utc
        )
        assert asn1.GeneralizedTime(dt).as_datetime() == dt

    def test_repr_generalized_time(self) -> None:
        dt = datetime.datetime(
            2000, 1, 1, 10, 10, 10, 300000, tzinfo=datetime.timezone.utc
        )
        assert repr(asn1.GeneralizedTime(dt)) == f"GeneralizedTime({dt!r})"

    def test_invalid_generalized_time(self) -> None:
        with pytest.raises(
            ValueError,
            match="cannot initialize with naive datetime object",
        ):
            # We don't allow naive datetime objects
            asn1.GeneralizedTime(datetime.datetime(2000, 1, 1, 10, 10, 10))

    def test_bitstring_getters(self) -> None:
        data = b"\x01\x02\x30"
        bt = asn1.BitString(data=data, padding_bits=2)

        assert bt.as_bytes() == data
        assert bt.padding_bits() == 2

    def test_repr_bitstring(self) -> None:
        data = b"\x01\x02\x30"
        assert (
            repr(asn1.BitString(data, 2))
            == f"BitString(data={data!r}, padding_bits=2)"
        )

    def test_invalid_bitstring(self) -> None:
        with pytest.raises(
            ValueError,
            match="invalid BIT STRING",
        ):
            # Padding bits cannot be > 7
            asn1.BitString(data=b"\x01\x02\x03", padding_bits=8)

        with pytest.raises(
            ValueError,
            match="invalid BIT STRING",
        ):
            # Padding bits have to be zero
            asn1.BitString(data=b"\x01\x02\x03", padding_bits=2)


class TestSequenceAPI:
    def test_fail_unsupported_field(self) -> None:
        # Not a sequence
        class Unsupported:
            foo: int

        with pytest.raises(TypeError, match="cannot handle type"):

            @asn1.sequence
            class Example:
                foo: Unsupported

    def test_fail_init_incorrect_field_name(self) -> None:
        @asn1.sequence
        class Example:
            foo: int

        with pytest.raises(
            TypeError, match="got an unexpected keyword argument 'bar'"
        ):
            Example(bar=3)  # type: ignore[call-arg]

    def test_fail_init_missing_field_name(self) -> None:
        @asn1.sequence
        class Example:
            foo: int

        expected_err = (
            "missing 1 required keyword-only argument: 'foo'"
            if sys.version_info >= (3, 10)
            else "missing 1 required positional argument: 'foo'"
        )

        with pytest.raises(TypeError, match=expected_err):
            Example()  # type: ignore[call-arg]

    def test_fail_positional_field_initialization(self) -> None:
        @asn1.sequence
        class Example:
            foo: int

        # The kw-only init is only enforced in Python >= 3.10, which is
        # when the parameter `kw_only` for `dataclasses.datalass` was
        # added.
        if sys.version_info < (3, 10):
            assert Example(5).foo == 5  # type: ignore[misc]
        else:
            with pytest.raises(
                TypeError,
                match="takes 1 positional argument but 2 were given",
            ):
                Example(5)  # type: ignore[misc]

    def test_fail_malformed_root_type(self) -> None:
        @asn1.sequence
        class Invalid:
            foo: int

        setattr(Invalid, "__asn1_root__", int)

        with pytest.raises(TypeError, match="unsupported root type"):

            @asn1.sequence
            class Example:
                foo: Invalid

    def test_fail_unsupported_union_field(self) -> None:
        with pytest.raises(
            TypeError,
            match="union types other than `X \\| None` are currently not "
            "supported",
        ):

            @asn1.sequence
            class Example:
                invalid: typing.Union[int, str]

    def test_fail_unsupported_annotation(self) -> None:
        with pytest.raises(
            TypeError, match="unsupported annotation: some annotation"
        ):

            @asn1.sequence
            class Example:
                invalid: Annotated[int, "some annotation"]

    def test_fail_unsupported_size_annotation(self) -> None:
        with pytest.raises(
            TypeError,
            match="field invalid has a SIZE annotation, but SIZE "
            "annotations are only supported for SEQUENCE OF fields",
        ):

            @asn1.sequence
            class Example:
                invalid: Annotated[int, asn1.Size(min=0, max=3)]

    def test_fail_multiple_default_annotations(self) -> None:
        with pytest.raises(
            TypeError,
            match="multiple DEFAULT annotations found in field 'invalid'",
        ):

            @asn1.sequence
            class Example:
                invalid: Annotated[
                    int, asn1.Default(value=8), asn1.Default(value=9)
                ]

    def test_fail_multiple_implicit_annotations(self) -> None:
        with pytest.raises(
            TypeError,
            match="multiple IMPLICIT/EXPLICIT annotations found in field "
            "'invalid'",
        ):

            @asn1.sequence
            class Example:
                invalid: Annotated[int, asn1.Implicit(0), asn1.Implicit(1)]

    def test_fail_multiple_explicit_annotations(self) -> None:
        with pytest.raises(
            TypeError,
            match="multiple IMPLICIT/EXPLICIT annotations found in field "
            "'invalid'",
        ):

            @asn1.sequence
            class Example:
                invalid: Annotated[int, asn1.Explicit(0), asn1.Explicit(1)]

    def test_fail_multiple_size_annotations(self) -> None:
        with pytest.raises(
            TypeError,
            match="multiple SIZE annotations found in field 'invalid'",
        ):

            @asn1.sequence
            class Example:
                invalid: Annotated[
                    int, asn1.Size(min=1, max=2), asn1.Size(min=1, max=2)
                ]

    def test_fail_optional_with_default_field(self) -> None:
        with pytest.raises(
            TypeError,
            match=re.escape(
                "optional (`X | None`) types should not have a "
                "DEFAULT annotation"
            ),
        ):

            @asn1.sequence
            class Example:
                invalid: Annotated[
                    typing.Union[int, None], asn1.Default(value=9)
                ]

    def test_fail_optional_with_annotations_inside(self) -> None:
        with pytest.raises(
            TypeError,
            match=re.escape(
                "optional (`X | None`) types cannot have `X` "
                "annotated: annotations must apply to the union (i.e: "
                "`Annotated[X | None, annotation]`)"
            ),
        ):

            @asn1.sequence
            class Example2:
                invalid: typing.Union[
                    Annotated[int, asn1.Default(value=9)], None
                ]

    def test_fields_of_variant_type(self) -> None:
        from cryptography.hazmat.bindings._rust import declarative_asn1

        # Needed for coverage of the `_0`, `_1`, etc fields generated
        # for tuple enum variants
        seq = declarative_asn1.Type.Sequence(type(None), {})
        assert seq._0 is type(None)
        assert seq._1 == {}

        ann_type = declarative_asn1.AnnotatedType(
            seq, declarative_asn1.Annotation()
        )
        opt = declarative_asn1.Type.Option(ann_type)
        assert opt._0 == ann_type

        seq_of = declarative_asn1.Type.SequenceOf(ann_type)
        assert seq_of._0 is ann_type

    def test_fields_of_variant_encoding(self) -> None:
        from cryptography.hazmat.bindings._rust import declarative_asn1

        # Needed for coverage of the `_0`, `_1`, etc fields generated
        # for tuple enum variants
        implicit = declarative_asn1.Encoding.Implicit(0)
        explicit = declarative_asn1.Encoding.Explicit(0)
        assert implicit._0 == 0
        assert explicit._0 == 0
