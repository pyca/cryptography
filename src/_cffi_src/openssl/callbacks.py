# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <string.h>
"""

TYPES = """
typedef struct {
    char *password;
    int length;
    int called;
    int error;
    int maxsize;
} CRYPTOGRAPHY_PASSWORD_DATA;
"""

FUNCTIONS = """
int Cryptography_pem_password_cb(char *, int, int, void *);
"""

CUSTOMIZATIONS = """
typedef struct {
    char *password;
    int length;
    int called;
    int error;
    int maxsize;
} CRYPTOGRAPHY_PASSWORD_DATA;

int Cryptography_pem_password_cb(char *buf, int size,
                                 int rwflag, void *userdata) {
    /* The password cb is only invoked if OpenSSL decides the private
       key is encrypted. So this path only occurs if it needs a password */
    CRYPTOGRAPHY_PASSWORD_DATA *st = (CRYPTOGRAPHY_PASSWORD_DATA *)userdata;
    st->called += 1;
    st->maxsize = size;
    if (st->length == 0) {
        st->error = -1;
        return 0;
    } else if (st->length < size) {
        memcpy(buf, st->password, (size_t)st->length);
        return st->length;
    } else {
        st->error = -2;
        return 0;
    }
}
"""
