# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

import typing

def openssl_version() -> int: ...
def raise_openssl_error() -> typing.NoReturn: ...
