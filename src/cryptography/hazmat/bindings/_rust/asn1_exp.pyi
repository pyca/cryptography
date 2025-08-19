# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.
from enum import Enum
from typing import Any, ClassVar

def encode_der(value: Any) -> bytes: ...

class RootType(Enum):
    Sequence = ...
    Set = ...

# Type is a Rust enum with tuple variants. For now, we express the type
# annotations like this:
class Type:
    Sequence: ClassVar[type]
    PyInt: ClassVar[type]

class Annotation:
    def __new__(
        cls,
    ) -> Annotation: ...

class AnnotatedType:
    inner: Type
    annotation: Annotation

    def __new__(cls, inner: Type, annotation: Annotation) -> AnnotatedType: ...

class AnnotatedTypeObject:
    annotated_type: AnnotatedType
    value: Any

    def __new__(
        cls, annotated_type: AnnotatedType, value: Any
    ) -> AnnotatedTypeObject: ...
