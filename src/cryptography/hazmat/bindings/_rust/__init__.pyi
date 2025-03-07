# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

from cryptography.hazmat.primitives import padding

class PKCS7PaddingContext(padding.PaddingContext):
    def __init__(self, block_size: int) -> None: ...
    def update(self, data: bytes) -> bytes: ...
    def finalize(self) -> bytes: ...

class ANSIX923PaddingContext(padding.PaddingContext):
    def __init__(self, block_size: int) -> None: ...
    def update(self, data: bytes) -> bytes: ...
    def finalize(self) -> bytes: ...

class PKCS7UnpaddingContext(padding.PaddingContext):
    def __init__(self, block_size: int) -> None: ...
    def update(self, data: bytes) -> bytes: ...
    def finalize(self) -> bytes: ...

class ANSIX923UnpaddingContext(padding.PaddingContext):
    def __init__(self, block_size: int) -> None: ...
    def update(self, data: bytes) -> bytes: ...
    def finalize(self) -> bytes: ...

class ObjectIdentifier:
    def __init__(self, value: str) -> None: ...
    @property
    def dotted_string(self) -> str: ...
    @property
    def _name(self) -> str: ...

T = typing.TypeVar("T")
