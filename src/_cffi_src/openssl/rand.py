# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/rand.h>
"""

TYPES = """
static const long Cryptography_HAS_EGD;
"""

FUNCTIONS = """
void RAND_seed(const void *, int);
void RAND_add(const void *, int, double);
int RAND_status(void);
const char *RAND_file_name(char *, size_t);
int RAND_load_file(const char *, long);
int RAND_write_file(const char *);
int RAND_bytes(unsigned char *, int);
/* ERR_load_RAND_strings started returning an int in 1.1.0. Unfortunately we
   can't declare a conditional signature like that. Since it always returns
   1 we'll just lie about the signature to preserve compatibility for
   pyOpenSSL (which calls this in its rand.py as of mid-2016) */
void ERR_load_RAND_strings(void);

/* RAND_cleanup became a macro in 1.1.0 */
void RAND_cleanup(void);
"""

CUSTOMIZATIONS = """
static const long Cryptography_HAS_EGD = 0;
"""
