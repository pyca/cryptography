# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/crypto.h>
"""

TYPES = """
static const int OPENSSL_VERSION;
static const int OPENSSL_CFLAGS;
static const int OPENSSL_BUILT_ON;
static const int OPENSSL_PLATFORM;
static const int OPENSSL_DIR;
"""

FUNCTIONS = """
void OPENSSL_cleanup(void);

unsigned long OpenSSL_version_num(void);
const char *OpenSSL_version(int);

void *OPENSSL_malloc(size_t);
void OPENSSL_free(void *);
"""

CUSTOMIZATIONS = """
"""
