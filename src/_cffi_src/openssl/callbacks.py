# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/crypto.h>

#ifdef _WIN32
#include <Windows.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#endif
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
int _setup_ssl_threads(void);
int Cryptography_pem_password_cb(char *, int, int, void *);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
/* This code is derived from the locking code found in the Python _ssl module's
   locking callback for OpenSSL.

   Copyright 2001-2016 Python Software Foundation; All Rights Reserved.

   It has been subsequently modified to use cross platform locking without
   using CPython APIs by Armin Rigo of the PyPy project.
*/

#ifdef _WIN32
typedef CRITICAL_SECTION mutex1_t;
static __inline void mutex1_init(mutex1_t *mutex) {
    InitializeCriticalSection(mutex);
}
static __inline void mutex1_lock(mutex1_t *mutex) {
    EnterCriticalSection(mutex);
}
static __inline void mutex1_unlock(mutex1_t *mutex) {
    LeaveCriticalSection(mutex);
}
#else
typedef pthread_mutex_t mutex1_t;
#define ASSERT_STATUS(call)                                           \
    if (call != 0) {                                                  \
        perror("Fatal error in callback initialization: " #call);     \
        abort();                                                      \
    }
static inline void mutex1_init(mutex1_t *mutex) {
#if !defined(pthread_mutexattr_default)
#  define pthread_mutexattr_default ((pthread_mutexattr_t *)NULL)
#endif
    ASSERT_STATUS(pthread_mutex_init(mutex, pthread_mutexattr_default));
}
static inline void mutex1_lock(mutex1_t *mutex) {
    ASSERT_STATUS(pthread_mutex_lock(mutex));
}
static inline void mutex1_unlock(mutex1_t *mutex) {
    ASSERT_STATUS(pthread_mutex_unlock(mutex));
}
#endif



static unsigned int _ssl_locks_count = 0;
static mutex1_t *_ssl_locks = NULL;

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
        mutex1_lock(_ssl_locks + n);
    } else {
        mutex1_unlock(_ssl_locks + n);
    }
}

static void init_mutexes(void)
{
    int i;
    for (i = 0;  i < _ssl_locks_count;  i++) {
        mutex1_init(_ssl_locks + i);
    }
}


int _setup_ssl_threads(void) {
    unsigned int i;

    if (_ssl_locks == NULL) {
        _ssl_locks_count = CRYPTO_num_locks();
        _ssl_locks = malloc(sizeof(mutex1_t) * _ssl_locks_count);
        if (_ssl_locks == NULL) {
            return 0;
        }
        memset(_ssl_locks, 0, sizeof(mutex1_t) * _ssl_locks_count);
        init_mutexes();
        CRYPTO_set_locking_callback(_ssl_thread_locking_function);
#ifndef _WIN32
        pthread_atfork(NULL, NULL, &init_mutexes);
#endif
    }
    return 1;
}

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
        memcpy(buf, st->password, st->length);
        return st->length;
    } else {
        st->error = -2;
        return 0;
    }
}
"""
