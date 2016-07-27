# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import sys

import cffi

INCLUDES = """
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
"""

TYPES = """
static const long Cryptography_STATIC_CALLBACKS;

/* crypto.h
 * CRYPTO_set_locking_callback
 * void (*cb)(int mode, int type, const char *file, int line)
 */
extern "Python" void Cryptography_locking_cb(int, int, const char *, int);

/* pem.h
 * int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
 */
extern "Python" int Cryptography_pem_password_cb(char *, int, int, void *);

/* rand.h
 * int (*bytes)(unsigned char *buf, int num);
 * int (*status)(void);
 */
extern "Python" int Cryptography_rand_bytes(unsigned char *, int);
extern "Python" int Cryptography_rand_status(void);
"""

FUNCTIONS = """
"""

MACROS = """
"""

CUSTOMIZATIONS = """
static const long Cryptography_STATIC_CALLBACKS = 1;
"""

if cffi.__version_info__ < (1, 4, 0) or sys.version_info >= (3, 5):
    # backwards compatibility for old cffi version on PyPy
    # and Python >=3.5 (https://github.com/pyca/cryptography/issues/2970)
    TYPES = "static const long Cryptography_STATIC_CALLBACKS;"
    CUSTOMIZATIONS = "static const long Cryptography_STATIC_CALLBACKS = 0;"
