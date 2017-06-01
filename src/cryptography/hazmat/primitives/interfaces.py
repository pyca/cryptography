# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.hazmat.primitives.mac import MACContext as _MACContext


MACContext = utils.deprecated(
    _MACContext,
    __name__,
    "MACContext was moved to cryptography.hazmat.primitives.mac.MACContext "
    "in version 1.9.",
    utils.DeprecatedIn19
)
