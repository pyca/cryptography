# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/bio.h>
"""

TYPES = """
typedef ... BIO;
typedef ... BIO_METHOD;
typedef ... BIO_ADDR;
"""

FUNCTIONS = """
int BIO_free(BIO *);
BIO *BIO_new_file(const char *, const char *);
int BIO_read(BIO *, void *, int);
int BIO_write(BIO *, const void *, int);

BIO *BIO_new(BIO_METHOD *);
const BIO_METHOD *BIO_s_mem(void);
BIO *BIO_new_mem_buf(const void *, int);
long BIO_set_mem_eof_return(BIO *, int);
long BIO_get_mem_data(BIO *, char **);
int BIO_should_read(BIO *);
int BIO_should_write(BIO *);
int BIO_should_io_special(BIO *);
int BIO_should_retry(BIO *);

BIO_ADDR *BIO_ADDR_new(void);
void BIO_ADDR_free(BIO_ADDR *);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_IS_LIBRESSL || CRYPTOGRAPHY_IS_BORINGSSL \
    || CRYPTOGRAPHY_IS_AWSLC

#if !defined(_WIN32)
#include <sys/socket.h>
#endif

#include <stdlib.h>
#if !CRYPTOGRAPHY_IS_AWSLC
typedef struct sockaddr BIO_ADDR;
#endif

BIO_ADDR *BIO_ADDR_new(void) {
    return malloc(sizeof(struct sockaddr_storage));
}

void BIO_ADDR_free(BIO_ADDR *ptr) {
    free(ptr);
}
#endif
"""
