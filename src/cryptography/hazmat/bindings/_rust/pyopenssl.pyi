# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import typing

SSLv23_METHOD: int
TLSv1_METHOD: int
TLSv1_1_METHOD: int
TLSv1_2_METHOD: int
TLS_METHOD: int
TLS_SERVER_METHOD: int
TLS_CLIENT_METHOD: int
DTLS_METHOD: int
DTLS_SERVER_METHOD: int
DTLS_CLIENT_METHOD: int

class Context:
    def __new__(cls, method: int) -> Context: ...
    @property
    def _context(self) -> typing.Any: ...
