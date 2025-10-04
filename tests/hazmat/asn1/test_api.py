# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import sys
import typing

import pytest

import cryptography.hazmat.asn1 as asn1


class TestTypesAPI:
    def test_repr_printable_string(self) -> None:
        my_string = "MyString"
        assert (
            repr(asn1.PrintableString(my_string))
            == f"PrintableString({my_string!r})"
        )

    def test_invalid_printable_string(self) -> None:
        with pytest.raises(ValueError, match="invalid PrintableString: café"):
            asn1.PrintableString("café")

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
