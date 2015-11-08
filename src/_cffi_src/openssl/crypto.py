# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/crypto.h>
"""

TYPES = """
static const long Cryptography_HAS_SSLEAY_NAMES;
static const long Cryptography_HAS_OPENSSL_NAMES;

typedef ... CRYPTO_THREADID;

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
static const int CRYPTO_WRITE;
static const int CRYPTO_LOCK_SSL;
"""

FUNCTIONS = """

void CRYPTO_free(void *);
int CRYPTO_mem_ctrl(int);
int CRYPTO_is_mem_check_on(void);
void CRYPTO_mem_leaks(struct bio_st *);
void CRYPTO_cleanup_all_ex_data(void);
int CRYPTO_num_locks(void);
void CRYPTO_set_locking_callback(void(*)(int, int, const char *, int));
void CRYPTO_set_id_callback(unsigned long (*)(void));
unsigned long (*CRYPTO_get_id_callback(void))(void);
void (*CRYPTO_get_locking_callback(void))(int, int, const char *, int);
void CRYPTO_lock(int, int, const char *, int);

void OPENSSL_free(void *);
"""

MACROS = """
/* SSLeay was removed in 1.1.0 */
unsigned long SSLeay(void);
const char *SSLeay_version(int);
/* these functions were added to replace the SSLeay functions in 1.1.0 */
unsigned long OpenSSL_version_num(void);
const char *OpenSSL_version(int);

void CRYPTO_add(int *, int, int);
void CRYPTO_malloc_init(void);
const char *Cryptography_openssl_version_text(void);
"""

CUSTOMIZATIONS = """
/* In 1.1.0 SSLeay has finally been retired. Let's add a helper function to
   replicate the functionality we need for the backend. */
const char *Cryptography_openssl_version_text(void) {
#if defined(SSLEAY_VERSION)
    return SSLeay_version(SSLEAY_VERSION);
#else
    return OpenSSL_version(OPENSSL_VERSION);
#endif
}

#if defined(SSLEAY_VERSION)
static const long Cryptography_HAS_SSLEAY_NAMES = 1;
#else
static const long Cryptography_HAS_SSLEAY_NAMES = 0;
static const int SSLEAY_VERSION = 0;
static const int SSLEAY_CFLAGS = 0;
static const int SSLEAY_PLATFORM = 0;
static const int SSLEAY_DIR = 0;
static const int SSLEAY_BUILT_ON = 0;
unsigned long (*SSLeay)(void) = NULL;
const char *(*SSLeay_version)(int) = NULL;
#endif
#if defined(OPENSSL_VERSION)
static const long Cryptography_HAS_OPENSSL_NAMES = 1;
#else
static const long Cryptography_HAS_OPENSSL_NAMES = 0;
static const int OPENSSL_VERSION = 0;
static const int OPENSSL_CFLAGS = 0;
static const int OPENSSL_BUILT_ON = 0;
static const int OPENSSL_PLATFORM = 0;
static const int OPENSSL_DIR = 0;
unsigned long (*OpenSSL_version_num)(void) = NULL;
const char *(*OpenSSL_version)(int) = NULL;
#endif
"""
