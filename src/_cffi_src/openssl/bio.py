# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/bio.h>
"""

TYPES = """
typedef ... BIO;
typedef ... BIO_METHOD;
"""

FUNCTIONS = """
int BIO_free(BIO *);
BIO *BIO_new_file(const char *, const char *);
int BIO_read(BIO *, void *, int);
int BIO_write(BIO *, const void *, int);

BIO *BIO_new(const BIO_METHOD *);
BIO_METHOD *BIO_s_mem(void);
BIO *BIO_new_mem_buf(const void *, int);
long BIO_set_mem_eof_return(BIO *, int);
long BIO_get_mem_data(BIO *, char **);
int BIO_should_read(BIO *);
int BIO_should_write(BIO *);
int BIO_should_io_special(BIO *);
int BIO_should_retry(BIO *);
int BIO_reset(BIO *);
"""

CUSTOMIZATIONS = """
"""
