# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import sys

import pytest

import cryptography.hazmat.asn1 as asn1


class TestTypesAPI:
    def test_repr_printable_string(self) -> None:
        assert (
            repr(asn1.PrintableString("MyString"))
            == "PrintableString(MyString)"
        )


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
