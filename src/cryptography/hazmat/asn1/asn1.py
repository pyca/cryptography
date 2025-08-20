# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import builtins
from typing import (
    Any,
    TypeVar,
)

import typing_extensions as te

from cryptography.hazmat.bindings._rust import asn1_exp

T = TypeVar("T", covariant=True)
U = TypeVar("U")


encode_der = asn1_exp.encode_der


def _normalize_field_type(
    field_type: Any, field_name: str
) -> asn1_exp.AnnotatedType:
    annotation = asn1_exp.Annotation()

    if field_type == builtins.int:
        rust_field_type = asn1_exp.Type.PyInt()
    elif hasattr(field_type, "__asn1_root__"):
        annotated_root = getattr(field_type, "__asn1_root__")
        if not isinstance(annotated_root, asn1_exp.AnnotatedType):
            raise TypeError(f"unsupported root type: {annotated_root}")
        return annotated_root
    else:
        raise TypeError(f"unsupported field type: {field_type}")

    return asn1_exp.AnnotatedType(rust_field_type, annotation)


def _annotate_fields(
    raw_fields: dict[str, type],
) -> dict[str, asn1_exp.AnnotatedType]:
    fields = {}
    for field_name, field_type in raw_fields.items():
        # Recursively normalize the field type into something that the
        # Rust code can understand.
        annotated_field_type = _normalize_field_type(field_type, field_name)
        fields[field_name] = annotated_field_type

    return fields


def _register_asn1_type(cls: type[U], root_type: asn1_exp.RootType) -> None:
    raw_fields = te.get_type_hints(cls, include_extras=True)
    setattr(cls, "__asn1_fields__", _annotate_fields(raw_fields))

    if root_type is asn1_exp.RootType.Sequence:
        root = asn1_exp.AnnotatedType(
            asn1_exp.Type.Sequence(cls), asn1_exp.Annotation()
        )
    else:
        raise TypeError(f"unsupported root type: {root_type}")

    setattr(cls, "__asn1_root__", root)

    def new_init(self: U, /, **kwargs: object) -> None:
        fields = dict(raw_fields)

        for arg_name, arg_value in kwargs.items():
            if fields.pop(arg_name, None):
                setattr(self, arg_name, arg_value)
            else:
                raise TypeError(f"invalid keyword argument: {arg_name}")

        # If fields is not empty, the user didn't supply enough arguments.
        if fields:
            raise TypeError(f"missing arguments: {', '.join(fields.keys())}")

    setattr(cls, "__init__", new_init)


@te.dataclass_transform(kw_only_default=True)
def sequence(cls: type[U]) -> type[U]:
    _register_asn1_type(cls, asn1_exp.RootType.Sequence)
    return cls
