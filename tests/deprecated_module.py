# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from cryptography import utils

# This module exists to test `cryptography.utils.deprecated`

DEPRECATED = utils.deprecated(
    3, __name__, "Test Deprecated Object", DeprecationWarning
)

NOT_DEPRECATED = 12
