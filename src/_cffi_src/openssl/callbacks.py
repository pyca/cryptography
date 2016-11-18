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
#include <openssl/crypto.h>

#include <pythread.h>
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
int _setup_ssl_threads(void);
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
    CUSTOMIZATIONS = """static const long Cryptography_STATIC_CALLBACKS = 0;
"""

CUSTOMIZATIONS += """
/* This code is derived from the locking code found in the Python _ssl module's
   locking callback for OpenSSL.

   Copyright 2001-2016 Python Software Foundation; All Rights Reserved.
*/

static unsigned int _ssl_locks_count = 0;
static PyThread_type_lock *_ssl_locks = NULL;

static void _ssl_thread_locking_function(int mode, int n, const char *file,
                                         int line) {
    /* this function is needed to perform locking on shared data
       structures. (Note that OpenSSL uses a number of global data
       structures that will be implicitly shared whenever multiple
       threads use OpenSSL.) Multi-threaded applications will
       crash at random if it is not set.

       locking_function() must be able to handle up to
       CRYPTO_num_locks() different mutex locks. It sets the n-th
       lock if mode & CRYPTO_LOCK, and releases it otherwise.

       file and line are the file number of the function setting the
       lock. They can be useful for debugging.
    */

    if ((_ssl_locks == NULL) ||
        (n < 0) || ((unsigned)n >= _ssl_locks_count)) {
        return;
    }

    if (mode & CRYPTO_LOCK) {
        PyThread_acquire_lock(_ssl_locks[n], 1);
    } else {
        PyThread_release_lock(_ssl_locks[n]);
    }
}

int _setup_ssl_threads(void) {
    unsigned int i;

    if (_ssl_locks == NULL) {
        _ssl_locks_count = CRYPTO_num_locks();
        _ssl_locks = PyMem_New(PyThread_type_lock, _ssl_locks_count);
        if (_ssl_locks == NULL) {
            PyErr_NoMemory();
            return 0;
        }
        memset(_ssl_locks, 0, sizeof(PyThread_type_lock) * _ssl_locks_count);
        for (i = 0;  i < _ssl_locks_count;  i++) {
            _ssl_locks[i] = PyThread_allocate_lock();
            if (_ssl_locks[i] == NULL) {
                unsigned int j;
                for (j = 0;  j < i;  j++) {
                    PyThread_free_lock(_ssl_locks[j]);
                }
                PyMem_Free(_ssl_locks);
                return 0;
            }
        }
        CRYPTO_set_locking_callback(_ssl_thread_locking_function);
    }
    return 1;
}
"""
