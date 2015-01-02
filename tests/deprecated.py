# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography.utils import deprecated_name

# This module only exists to support the module deprecation tests in
# test_deprecated.py

old_name = deprecated_name(
    1,
    __name__,
    "This name is deprecated.",
    DeprecationWarning
)

new_name = 2


