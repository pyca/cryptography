# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/crypto.h>
"""

TYPES = """
static const long Cryptography_HAS_LOCKING_CALLBACKS;
static const long Cryptography_HAS_MEM_FUNCTIONS;
static const long Cryptography_HAS_OPENSSL_CLEANUP;

static const int SSLEAY_VERSION;
static const int SSLEAY_CFLAGS;
static const int SSLEAY_PLATFORM;
static const int SSLEAY_DIR;
static const int SSLEAY_BUILT_ON;
static const int OPENSSL_VERSION;
static const int OPENSSL_CFLAGS;
static const int OPENSSL_BUILT_ON;
static const int OPENSSL_PLATFORM;
static const int OPENSSL_DIR;
static const int CRYPTO_MEM_CHECK_ON;
static const int CRYPTO_MEM_CHECK_OFF;
static const int CRYPTO_MEM_CHECK_ENABLE;
static const int CRYPTO_MEM_CHECK_DISABLE;
static const int CRYPTO_LOCK;
static const int CRYPTO_UNLOCK;
static const int CRYPTO_READ;
static const int CRYPTO_LOCK_SSL;
"""

FUNCTIONS = """
int CRYPTO_mem_ctrl(int);

void CRYPTO_cleanup_all_ex_data(void);
void OPENSSL_cleanup(void);

/* as of 1.1.0 OpenSSL does its own locking *angelic chorus*. These functions
   have become macros that are no ops */
int CRYPTO_num_locks(void);
void CRYPTO_set_locking_callback(void(*)(int, int, const char *, int));
void (*CRYPTO_get_locking_callback(void))(int, int, const char *, int);

/* SSLeay was removed in 1.1.0 */
unsigned long SSLeay(void);
const char *SSLeay_version(int);
/* these functions were added to replace the SSLeay functions in 1.1.0 */
unsigned long OpenSSL_version_num(void);
const char *OpenSSL_version(int);

/* this is a macro in 1.1.0 */
void *OPENSSL_malloc(size_t);
void OPENSSL_free(void *);

/* This was removed in 1.1.0 */
void CRYPTO_lock(int, int, const char *, int);

/* Signature changed significantly in 1.1.0, only expose there for sanity */
int Cryptography_CRYPTO_set_mem_functions(
    void *(*)(size_t, const char *, int),
    void *(*)(void *, size_t, const char *, int),
    void (*)(void *, const char *, int));

void *Cryptography_malloc_wrapper(size_t, const char *, int);
void *Cryptography_realloc_wrapper(void *, size_t, const char *, int);
void Cryptography_free_wrapper(void *, const char *, int);
"""

CUSTOMIZATIONS = """
/* In 1.1.0 SSLeay has finally been retired. We bidirectionally define the
   values so you can use either one. This is so we can use the new function
   names no matter what OpenSSL we're running on, but users on older pyOpenSSL
   releases won't see issues if they're running OpenSSL 1.1.0 */
#if !defined(SSLEAY_VERSION)
# define SSLeay                  OpenSSL_version_num
# define SSLeay_version          OpenSSL_version
# define SSLEAY_VERSION_NUMBER   OPENSSL_VERSION_NUMBER
# define SSLEAY_VERSION          OPENSSL_VERSION
# define SSLEAY_CFLAGS           OPENSSL_CFLAGS
# define SSLEAY_BUILT_ON         OPENSSL_BUILT_ON
# define SSLEAY_PLATFORM         OPENSSL_PLATFORM
# define SSLEAY_DIR              OPENSSL_DIR
#endif
#if !defined(OPENSSL_VERSION)
# define OpenSSL_version_num     SSLeay
# define OpenSSL_version         SSLeay_version
# define OPENSSL_VERSION         SSLEAY_VERSION
# define OPENSSL_CFLAGS          SSLEAY_CFLAGS
# define OPENSSL_BUILT_ON        SSLEAY_BUILT_ON
# define OPENSSL_PLATFORM        SSLEAY_PLATFORM
# define OPENSSL_DIR             SSLEAY_DIR
#endif
#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_110
static const long Cryptography_HAS_LOCKING_CALLBACKS = 1;
#else
static const long Cryptography_HAS_LOCKING_CALLBACKS = 0;
#if !defined(CRYPTO_LOCK)
static const long CRYPTO_LOCK = 0;
#endif
#if !defined(CRYPTO_UNLOCK)
static const long CRYPTO_UNLOCK = 0;
#endif
#if !defined(CRYPTO_READ)
static const long CRYPTO_READ = 0;
#endif
#if !defined(CRYPTO_LOCK_SSL)
static const long CRYPTO_LOCK_SSL = 0;
#endif
void (*CRYPTO_lock)(int, int, const char *, int) = NULL;
#endif

#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_110
static const long Cryptography_HAS_OPENSSL_CLEANUP = 0;

void (*OPENSSL_cleanup)(void) = NULL;

/* This function has a significantly different signature pre-1.1.0. since it is
 * for testing only, we don't bother to expose it on older OpenSSLs.
 */
static const long Cryptography_HAS_MEM_FUNCTIONS = 0;
int (*Cryptography_CRYPTO_set_mem_functions)(
    void *(*)(size_t, const char *, int),
    void *(*)(void *, size_t, const char *, int),
    void (*)(void *, const char *, int)) = NULL;

#else
static const long Cryptography_HAS_OPENSSL_CLEANUP = 1;
static const long Cryptography_HAS_MEM_FUNCTIONS = 1;

int Cryptography_CRYPTO_set_mem_functions(
    void *(*m)(size_t, const char *, int),
    void *(*r)(void *, size_t, const char *, int),
    void (*f)(void *, const char *, int)
) {
    return CRYPTO_set_mem_functions(m, r, f);
}
#endif

void *Cryptography_malloc_wrapper(size_t size, const char *path, int line) {
    return malloc(size);
}

void *Cryptography_realloc_wrapper(void *ptr, size_t size, const char *path,
                                   int line) {
    return realloc(ptr, size);
}

void Cryptography_free_wrapper(void *ptr, const char *path, int line) {
    free(ptr);
}
"""
