# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/tls1.h>
"""

TYPES = """
"""

FUNCTIONS = """
long Cryptography_SSL_CTX_set_tlsext_servername_callback(SSL_CTX *, int(*)(SSL*,int*,void*));
long Cryptography_SSL_CTX_set_tlsext_servername_arg(SSL_CTX *, void * arg);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
long Cryptography_SSL_CTX_set_tlsext_servername_callback(SSL_CTX * ctx, int(*cb)(SSL*,int*,void*)) {
    return SSL_CTX_set_tlsext_servername_callback(ctx, cb);
}
long Cryptography_SSL_CTX_set_tlsext_servername_arg(SSL_CTX * ctx, void *arg) {
    return SSL_CTX_set_tlsext_servername_arg(ctx, arg);
}
"""
