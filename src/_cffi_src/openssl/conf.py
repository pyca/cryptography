# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/conf.h>
"""

TYPES = """
"""

FUNCTIONS = """
void OPENSSL_config(const char *);
/* This is a macro in 1.1.0 */
void OPENSSL_no_config(void);
"""

CUSTOMIZATIONS = """
#if (OPENSSL_API_COMPAT >= 0x10100000L) && !CRYPTOGRAPHY_IS_LIBRESSL
#define OPENSSL_config(x) 0
#define OPENSSL_no_config() 0
#endif
"""
