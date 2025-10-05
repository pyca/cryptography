# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import datetime
import typing

def decode_der(cls: type, value: bytes) -> typing.Any: ...
def encode_der(value: typing.Any) -> bytes: ...
def non_root_python_to_rust(cls: type) -> Type: ...

# Type is a Rust enum with tuple variants. For now, we express the type
# annotations like this:
class Type:
    Sequence: typing.ClassVar[type]
    Option: typing.ClassVar[type]
    PyBool: typing.ClassVar[type]
    PyInt: typing.ClassVar[type]
    PyBytes: typing.ClassVar[type]
    PyStr: typing.ClassVar[type]

class Annotation:
    default: Default | None
    def __new__(
        cls,
        default: Default | None = None,
    ) -> Annotation: ...

T = typing.TypeVar("T")

# TODO: replace with `Default[T]` once the min Python version is >= 3.12
class Default(typing.Generic[T]):
    value: T

    def __new__(cls, value: T) -> Default: ...

class AnnotatedType:
    inner: Type
    annotation: Annotation

    def __new__(cls, inner: Type, annotation: Annotation) -> AnnotatedType: ...

class AnnotatedTypeObject:
    annotated_type: AnnotatedType
    value: typing.Any

    def __new__(
        cls, annotated_type: AnnotatedType, value: typing.Any
    ) -> AnnotatedTypeObject: ...

class PrintableString:
    def __new__(cls, inner: str) -> PrintableString: ...
    def __repr__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def as_str(self) -> str: ...

class UtcTime:
    def __new__(cls, inner: datetime.datetime) -> UtcTime: ...
    def __repr__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def as_datetime(self) -> datetime.datetime: ...

class GeneralizedTime:
    def __new__(cls, inner: datetime.datetime) -> GeneralizedTime: ...
    def __repr__(self) -> str: ...
    def __eq__(self, other: object) -> bool: ...
    def as_datetime(self) -> datetime.datetime: ...
