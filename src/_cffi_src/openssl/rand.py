# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/rand.h>
"""

TYPES = """
typedef ... RAND_METHOD;
"""

FUNCTIONS = """
int RAND_set_rand_method(const RAND_METHOD *);
void RAND_add(const void *, int, double);
int RAND_status(void);
int RAND_bytes(unsigned char *, int);
"""

CUSTOMIZATIONS = """
"""
