# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

from cryptography import utils
from cryptography.hazmat.primitives.mac import cmac

CMAC = utils.deprecated(
    cmac.CMAC,
    __name__,
    (
        "The CMAC class has moved to the "
        "cryptography.hazmat.primitives.mac.cmac module"
    ),
    utils.DeprecatedIn08
)
