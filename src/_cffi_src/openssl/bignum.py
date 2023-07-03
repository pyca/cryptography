# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/bn.h>
"""

TYPES = """
static const long Cryptography_HAS_PRIME_CHECKS;

typedef ... BN_CTX;
typedef ... BIGNUM;
typedef int... BN_ULONG;
"""

FUNCTIONS = """
BIGNUM *BN_new(void);
void BN_free(BIGNUM *);
void BN_clear_free(BIGNUM *);

int BN_rand_range(BIGNUM *, const BIGNUM *);

int BN_set_word(BIGNUM *, BN_ULONG);

char *BN_bn2hex(const BIGNUM *);
int BN_hex2bn(BIGNUM **, const char *);

int BN_bn2bin(const BIGNUM *, unsigned char *);
BIGNUM *BN_bin2bn(const unsigned char *, int, BIGNUM *);

int BN_num_bits(const BIGNUM *);

int BN_is_negative(const BIGNUM *);
int BN_is_odd(const BIGNUM *);

int BN_num_bytes(const BIGNUM *);

/* The following 3 prime methods are exposed for Tribler. */
int BN_generate_prime_ex(BIGNUM *, int, int, const BIGNUM *,
                         const BIGNUM *, BN_GENCB *);
int BN_is_prime_ex(const BIGNUM *, int, BN_CTX *, BN_GENCB *);
const int BN_prime_checks_for_size(int);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_PRIME_CHECKS = 0;
int (*BN_prime_checks_for_size)(int) = NULL;
#else
static const long Cryptography_HAS_PRIME_CHECKS = 1;
#endif
"""
