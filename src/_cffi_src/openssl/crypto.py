# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/crypto.h>
"""

TYPES = """
static const long Cryptography_HAS_MEM_FUNCTIONS;
static const long Cryptography_HAS_OPENSSL_CLEANUP;

static const int OPENSSL_VERSION;
static const int OPENSSL_CFLAGS;
static const int OPENSSL_BUILT_ON;
static const int OPENSSL_PLATFORM;
static const int OPENSSL_DIR;
"""

FUNCTIONS = """
void OPENSSL_cleanup(void);

unsigned long OpenSSL_version_num(void);
const char *OpenSSL_version(int);

void *OPENSSL_malloc(size_t);
void OPENSSL_free(void *);


/* Signature is significantly different in LibreSSL, so expose via different
   symbol name */
int Cryptography_CRYPTO_set_mem_functions(
    void *(*)(size_t, const char *, int),
    void *(*)(void *, size_t, const char *, int),
    void (*)(void *, const char *, int));

void *Cryptography_malloc_wrapper(size_t, const char *, int);
void *Cryptography_realloc_wrapper(void *, size_t, const char *, int);
void Cryptography_free_wrapper(void *, const char *, int);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_LIBRESSL_LESS_THAN_360
static const long Cryptography_HAS_OPENSSL_CLEANUP = 0;
void (*OPENSSL_cleanup)(void) = NULL;
#else
static const long Cryptography_HAS_OPENSSL_CLEANUP = 1;
#endif

#if CRYPTOGRAPHY_IS_LIBRESSL || CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_MEM_FUNCTIONS = 0;
int (*Cryptography_CRYPTO_set_mem_functions)(
    void *(*)(size_t, const char *, int),
    void *(*)(void *, size_t, const char *, int),
    void (*)(void *, const char *, int)) = NULL;

#else
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
