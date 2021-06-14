# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/ecdh.h>
"""

TYPES = """
"""

FUNCTIONS = """
long SSL_CTX_set_ecdh_auto(SSL_CTX *, int);
"""

CUSTOMIZATIONS = """
"""
