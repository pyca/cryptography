# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/bn.h>
"""

TYPES = """
typedef ... BN_CTX;
typedef ... BIGNUM;
typedef int... BN_ULONG;
"""

FUNCTIONS = """
BIGNUM *BN_new(void);
void BN_free(BIGNUM *);
void BN_clear_free(BIGNUM *);

BN_CTX *BN_CTX_new(void);
void BN_CTX_free(BN_CTX *);

void BN_CTX_start(BN_CTX *);
BIGNUM *BN_CTX_get(BN_CTX *);
void BN_CTX_end(BN_CTX *);

BIGNUM *BN_dup(const BIGNUM *);

int BN_set_word(BIGNUM *, BN_ULONG);

char *BN_bn2hex(const BIGNUM *);
int BN_hex2bn(BIGNUM **, const char *);

int BN_bn2bin(const BIGNUM *, unsigned char *);
BIGNUM *BN_bin2bn(const unsigned char *, int, BIGNUM *);

int BN_num_bits(const BIGNUM *);
int BN_num_bytes(const BIGNUM *);
"""

CUSTOMIZATIONS = """
"""
