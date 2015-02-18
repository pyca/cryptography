# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.hazmat.primitives.mac import hmac

HMAC = utils.deprecated(
    hmac.HMAC,
    __name__,
    (
        "The HMAC class has moved to the "
        "cryptography.hazmat.primitives.mac.hmac module"
    ),
    utils.DeprecatedIn08
)
