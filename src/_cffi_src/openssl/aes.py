# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/aes.h>
"""

TYPES = """
typedef ... AES_KEY;
"""

FUNCTIONS = """
int AES_wrap_key(AES_KEY *, const unsigned char *, unsigned char *,
                 const unsigned char *, unsigned int);
int AES_unwrap_key(AES_KEY *, const unsigned char *, unsigned char *,
                   const unsigned char *, unsigned int);
"""

CUSTOMIZATIONS = """
"""
