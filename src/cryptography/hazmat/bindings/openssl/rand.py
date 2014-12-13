# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/rand.h>
"""

TYPES = """
"""

FUNCTIONS = """
void ERR_load_RAND_strings(void);
void RAND_seed(const void *, int);
void RAND_add(const void *, int, double);
int RAND_status(void);
int RAND_egd(const char *);
int RAND_egd_bytes(const char *, int);
int RAND_query_egd_bytes(const char *, unsigned char *, int);
const char *RAND_file_name(char *, size_t);
int RAND_load_file(const char *, long);
int RAND_write_file(const char *);
void RAND_cleanup(void);
int RAND_bytes(unsigned char *, int);
int RAND_pseudo_bytes(unsigned char *, int);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
