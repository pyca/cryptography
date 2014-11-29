# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <Security/SecItem.h>
"""

TYPES = """
const CFTypeRef kSecAttrKeyType;
const CFTypeRef kSecAttrKeySizeInBits;
const CFTypeRef kSecAttrIsPermanent;
const CFTypeRef kSecAttrKeyTypeRSA;
const CFTypeRef kSecAttrKeyTypeDSA;
const CFTypeRef kSecAttrKeyTypeEC;
const CFTypeRef kSecUseKeychain;

const CFTypeRef kSecAttrKeyClass;
const CFTypeRef kSecAttrKeyClassPublic;
const CFTypeRef kSecAttrKeyClassPrivate;
const CFTypeRef kSecAttrKeyClassSymmetric;

"""

FUNCTIONS = """
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
