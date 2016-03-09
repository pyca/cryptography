# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/crypto.h>
"""

TYPES = """
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
"""
