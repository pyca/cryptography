# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/dh.h>
"""

TYPES = """
typedef ... DH;
"""

FUNCTIONS = """
DH *DH_new(void);
void DH_free(DH *);
int DH_size(const DH *);
int DH_check(const DH *, int *);
int DH_check_pub_key(const DH *, const BIGNUM *, int *);
int DH_generate_key(DH *);
int DH_compute_key(unsigned char *, const BIGNUM *, DH *);
int DH_set_ex_data(DH *, int, void *);
void *DH_get_ex_data(DH *, int);
DH *d2i_DHparams(DH **, const unsigned char **, long);
int i2d_DHparams(const DH *, unsigned char **);
int DHparams_print_fp(FILE *, const DH *);
int DHparams_print(BIO *, const DH *);
DH *DHparams_dup(DH *);

/* added in 1.1.0 when the DH struct was opaqued */
void DH_get0_pqg(const DH *, const BIGNUM **, const BIGNUM **,
                 const BIGNUM **);
int DH_set0_pqg(DH *, BIGNUM *, BIGNUM *, BIGNUM *);
void DH_get0_key(const DH *, const BIGNUM **, const BIGNUM **);
int DH_set0_key(DH *, BIGNUM *, BIGNUM *);
"""

MACROS = """
int DH_generate_parameters_ex(DH *, int, int, BN_GENCB *);
"""

CUSTOMIZATIONS = """
/* These functions were added in OpenSSL 1.1.0-pre5 (beta2) */
#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_110PRE5 || defined(LIBRESSL_VERSION_NUMBER)
void DH_get0_pqg(const DH *dh,
                 const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    if (p != NULL)
        *p = dh->p;
    if (q != NULL)
        *q = dh->q;
    if (g != NULL)
        *g = dh->g;
}

int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* If the fields p and g in d are NULL, the corresponding input
     * parameters MUST be non-NULL.  q may remain NULL.
     */
    if ((dh->p == NULL && p == NULL)
        || (dh->g == NULL && g == NULL))
        return 0;

    if (p != NULL) {
        BN_free(dh->p);
        dh->p = p;
    }
    if (q != NULL) {
        BN_free(dh->q);
        dh->q = q;
    }
    if (g != NULL) {
        BN_free(dh->g);
        dh->g = g;
    }

    if (q != NULL) {
        dh->length = BN_num_bits(q);
    }

    return 1;
}

void DH_get0_key(const DH *dh, const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = dh->pub_key;
    if (priv_key != NULL)
        *priv_key = dh->priv_key;
}

int DH_set0_key(DH *dh, BIGNUM *pub_key, BIGNUM *priv_key)
{
    /* If the field pub_key in dh is NULL, the corresponding input
     * parameters MUST be non-NULL.  The priv_key field may
     * be left NULL.
     */
    if (dh->pub_key == NULL && pub_key == NULL)
        return 0;

    if (pub_key != NULL) {
        BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(dh->priv_key);
        dh->priv_key = priv_key;
    }

    return 1;
}
#endif
"""
