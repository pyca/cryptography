# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <CommonCrypto/CommonSymmetricKeywrap.h>
"""

TYPES = """
enum {
    kCCWRAPAES = 1,
};

typedef uint32_t CCWrappingAlgorithm;
"""

FUNCTIONS = """
int CCSymmetricKeyWrap(CCWrappingAlgorithm, const uint8_t *, const size_t,
                        const uint8_t *, size_t, const uint8_t *, size_t,
                        uint8_t *, size_t *);
int CCSymmetricKeyUnwrap(CCWrappingAlgorithm algorithm, const uint8_t *,
                         const size_t, const uint8_t *, size_t,
                         const uint8_t *, size_t, uint8_t *, size_t *);
size_t CCSymmetricWrappedSize(CCWrappingAlgorithm, size_t);
size_t CCSymmetricUnwrappedSize(CCWrappingAlgorithm, size_t);

"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
