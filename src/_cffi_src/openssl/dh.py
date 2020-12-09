# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/dh.h>
"""

TYPES = """
typedef ... DH;

const long DH_NOT_SUITABLE_GENERATOR;
"""

FUNCTIONS = """
DH *DH_new(void);
void DH_free(DH *);
int DH_size(const DH *);
int DH_generate_key(DH *);
int DH_compute_key(unsigned char *, const BIGNUM *, DH *);
DH *DHparams_dup(DH *);

/* added in 1.1.0 when the DH struct was opaqued */
void DH_get0_pqg(const DH *, const BIGNUM **, const BIGNUM **,
                 const BIGNUM **);
int DH_set0_pqg(DH *, BIGNUM *, BIGNUM *, BIGNUM *);
void DH_get0_key(const DH *, const BIGNUM **, const BIGNUM **);
int DH_set0_key(DH *, BIGNUM *, BIGNUM *);

int Cryptography_DH_check(const DH *, int *);
int DH_generate_parameters_ex(DH *, int, int, BN_GENCB *);
DH *d2i_DHparams_bio(BIO *, DH **);
int i2d_DHparams_bio(BIO *, DH *);
DH *Cryptography_d2i_DHxparams_bio(BIO *bp, DH **x);
int Cryptography_i2d_DHxparams_bio(BIO *bp, DH *x);
"""

CUSTOMIZATIONS = """
int Cryptography_DH_check(const DH *dh, int *ret) {
    return DH_check(dh, ret);
}

/* These functions were added in OpenSSL 1.1.0f commit d0c50e80a8 */
/* Define our own to simplify support across all versions. */
#if defined(EVP_PKEY_DHX) && EVP_PKEY_DHX != -1
DH *Cryptography_d2i_DHxparams_bio(BIO *bp, DH **x) {
    return ASN1_d2i_bio_of(DH, DH_new, d2i_DHxparams, bp, x);
}
int Cryptography_i2d_DHxparams_bio(BIO *bp, DH *x) {
    return ASN1_i2d_bio_of_const(DH, i2d_DHxparams, bp, x);
}
#else
DH *(*Cryptography_d2i_DHxparams_bio)(BIO *bp, DH **x) = NULL;
int (*Cryptography_i2d_DHxparams_bio)(BIO *bp, DH *x) = NULL;
#endif
"""
