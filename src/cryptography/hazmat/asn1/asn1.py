# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import dataclasses
import sys
import types
import typing

if sys.version_info < (3, 11):
    import typing_extensions

    # We use the `include_extras` parameter of `get_type_hints`, which was
    # added in Python 3.9. This can be replaced by the `typing` version
    # once the min version is >= 3.9
    if sys.version_info < (3, 9):
        get_type_hints = typing_extensions.get_type_hints
        get_type_args = typing_extensions.get_args
        Annotated = typing_extensions.Annotated
    else:
        get_type_hints = typing.get_type_hints
        get_type_args = typing.get_args
        Annotated = typing.Annotated
else:
    get_type_hints = typing.get_type_hints
    get_type_args = typing.get_args
    Annotated = typing.Annotated

if sys.version_info < (3, 10):
    NoneType = type(None)
else:
    NoneType = types.NoneType  # type: ignore[valid-type]

from cryptography.hazmat.bindings._rust import declarative_asn1

T = typing.TypeVar("T", covariant=True)
U = typing.TypeVar("U")


decode_der = declarative_asn1.decode_der
encode_der = declarative_asn1.encode_der


def _is_union(field_type: type) -> bool:
    # NOTE: types.UnionType for `T | U`, typing.Union for `Union[T, U]`.
    # TODO: Drop the `hasattr()` once the minimum supported Python version
    # is >= 3.10.
    union_types = (
        (types.UnionType, typing.Union)
        if hasattr(types, "UnionType")
        else (typing.Union,)
    )
    return typing.get_origin(field_type) in union_types


def _extract_annotation(metadata: tuple) -> declarative_asn1.Annotation:
    default = None
    for raw_annotation in metadata:
        if isinstance(raw_annotation, declarative_asn1.Default):
            default = declarative_asn1.Default(value=raw_annotation.value)
        else:
            raise TypeError(f"unsupported annotation: {raw_annotation}")

    return declarative_asn1.Annotation(default=default)


def _normalize_field_type(
    field_type: typing.Any, field_name: str
) -> declarative_asn1.AnnotatedType:
    if typing.get_origin(field_type) is Annotated:
        annotation = _extract_annotation(field_type.__metadata__)
        field_type = get_type_args(field_type)[0]
    else:
        annotation = declarative_asn1.Annotation()

    if hasattr(field_type, "__asn1_root__"):
        annotated_root = field_type.__asn1_root__
        if not isinstance(annotated_root, declarative_asn1.AnnotatedType):
            raise TypeError(f"unsupported root type: {annotated_root}")
        return annotated_root
    elif _is_union(field_type):
        union_args = get_type_args(field_type)
        if len(union_args) == 2 and NoneType in union_args:
            # A Union between a type and None is an OPTIONAL
            optional_type = (
                union_args[0] if union_args[1] is type(None) else union_args[1]
            )
            annotated_type = _normalize_field_type(optional_type, field_name)

            if (
                annotation.default is not None
                or annotated_type.annotation.default is not None
            ):
                raise TypeError(
                    "optional (`X | None`) types should not have a DEFAULT "
                    "annotation"
                )
            rust_field_type = declarative_asn1.Type.Option(annotated_type)
        else:
            raise TypeError(
                "union types other than `X | None` are currently not supported"
            )
    else:
        rust_field_type = declarative_asn1.non_root_python_to_rust(field_type)

    return declarative_asn1.AnnotatedType(rust_field_type, annotation)


def _annotate_fields(
    raw_fields: dict[str, type],
) -> dict[str, declarative_asn1.AnnotatedType]:
    fields = {}
    for field_name, field_type in raw_fields.items():
        # Recursively normalize the field type into something that the
        # Rust code can understand.
        annotated_field_type = _normalize_field_type(field_type, field_name)
        fields[field_name] = annotated_field_type

    return fields


def _register_asn1_sequence(cls: type[U]) -> None:
    raw_fields = get_type_hints(cls, include_extras=True)
    root = declarative_asn1.AnnotatedType(
        declarative_asn1.Type.Sequence(cls, _annotate_fields(raw_fields)),
        declarative_asn1.Annotation(),
    )

    setattr(cls, "__asn1_root__", root)


# Due to https://github.com/python/mypy/issues/19731, we can't define an alias
# for `dataclass_transform` that conditionally points to `typing` or
# `typing_extensions` depending on the Python version (like we do for
# `get_type_hints`).
# We work around it by making the whole decorated class conditional on the
# Python version.
if sys.version_info < (3, 11):

    @typing_extensions.dataclass_transform(kw_only_default=True)
    def sequence(cls: type[U]) -> type[U]:
        # We use `dataclasses.dataclass` to add an __init__ method
        # to the class with keyword-only parameters.
        if sys.version_info >= (3, 10):
            dataclass_cls = dataclasses.dataclass(
                repr=False,
                eq=False,
                # `match_args` was added in Python 3.10 and defaults
                # to True
                match_args=False,
                # `kw_only` was added in Python 3.10 and defaults to
                # False
                kw_only=True,
            )(cls)
        else:
            dataclass_cls = dataclasses.dataclass(
                repr=False,
                eq=False,
            )(cls)
        _register_asn1_sequence(dataclass_cls)
        return dataclass_cls

else:

    @typing.dataclass_transform(kw_only_default=True)
    def sequence(cls: type[U]) -> type[U]:
        # Only add an __init__ method, with keyword-only
        # parameters.
        dataclass_cls = dataclasses.dataclass(
            repr=False,
            eq=False,
            match_args=False,
            kw_only=True,
        )(cls)
        _register_asn1_sequence(dataclass_cls)
        return dataclass_cls


Default = declarative_asn1.Default
PrintableString = declarative_asn1.PrintableString
UtcTime = declarative_asn1.UtcTime
GeneralizedTime = declarative_asn1.GeneralizedTime
