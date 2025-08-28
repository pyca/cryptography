# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import pytest

import cryptography.hazmat.asn1 as asn1


class TestClassAPI:
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

        with pytest.raises(
            TypeError, match="missing 1 required keyword-only argument: 'foo'"
        ):
            Example()  # type: ignore[call-arg]

    def test_fail_malformed_root_type(self) -> None:
        @asn1.sequence
        class Invalid:
            foo: int

        setattr(Invalid, "__asn1_root__", int)

        with pytest.raises(TypeError, match="unsupported root type"):

            @asn1.sequence
            class Example:
                foo: Invalid
