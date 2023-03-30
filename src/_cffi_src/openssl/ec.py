# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
"""

TYPES = """
static const int OPENSSL_EC_NAMED_CURVE;

typedef ... EC_KEY;
typedef ... EC_GROUP;
typedef ... EC_POINT;
typedef struct {
    int nid;
    const char *comment;
} EC_builtin_curve;
typedef enum {
    POINT_CONVERSION_COMPRESSED,
    POINT_CONVERSION_UNCOMPRESSED,
    ...
} point_conversion_form_t;
"""

FUNCTIONS = """
void EC_GROUP_free(EC_GROUP *);

EC_GROUP *EC_GROUP_new_by_curve_name(int);

int EC_GROUP_get_curve_name(const EC_GROUP *);

size_t EC_get_builtin_curves(EC_builtin_curve *, size_t);

EC_KEY *EC_KEY_new(void);
void EC_KEY_free(EC_KEY *);

EC_KEY *EC_KEY_new_by_curve_name(int);
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *);
const BIGNUM *EC_KEY_get0_private_key(const EC_KEY *);
int EC_KEY_set_private_key(EC_KEY *, const BIGNUM *);
const EC_POINT *EC_KEY_get0_public_key(const EC_KEY *);
int EC_KEY_set_public_key(EC_KEY *, const EC_POINT *);
void EC_KEY_set_asn1_flag(EC_KEY *, int);
int EC_KEY_generate_key(EC_KEY *);

EC_POINT *EC_POINT_new(const EC_GROUP *);
void EC_POINT_free(EC_POINT *);
int EC_POINT_cmp(const EC_GROUP *, const EC_POINT *, const EC_POINT *,
                 BN_CTX *);

int EC_POINT_set_affine_coordinates(const EC_GROUP *, EC_POINT *,
                                    const BIGNUM *, const BIGNUM *, BN_CTX *);
int EC_POINT_get_affine_coordinates(const EC_GROUP *, const EC_POINT *,
                                    BIGNUM *, BIGNUM *, BN_CTX *);

size_t EC_POINT_point2oct(const EC_GROUP *, const EC_POINT *,
    point_conversion_form_t,
    unsigned char *, size_t, BN_CTX *);

int EC_POINT_oct2point(const EC_GROUP *, EC_POINT *,
    const unsigned char *, size_t, BN_CTX *);

int EC_POINT_is_at_infinity(const EC_GROUP *, const EC_POINT *);

int EC_POINT_mul(const EC_GROUP *, EC_POINT *, const BIGNUM *,
    const EC_POINT *, const BIGNUM *, BN_CTX *);

const char *EC_curve_nid2nist(int);

int EC_GROUP_get_asn1_flag(const EC_GROUP *);
"""

CUSTOMIZATIONS = """
"""
