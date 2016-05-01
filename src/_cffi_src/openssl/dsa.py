# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/dsa.h>
"""

TYPES = """
typedef struct dsa_st {
    /* Prime number (public) */
    BIGNUM *p;
    /* Subprime (160-bit, q | p-1, public) */
    BIGNUM *q;
    /* Generator of subgroup (public) */
    BIGNUM *g;
    /* Private key x */
    BIGNUM *priv_key;
    /* Public key y = g^x */
    BIGNUM *pub_key;
    ...;
} DSA;
"""

FUNCTIONS = """
DSA *DSA_generate_parameters(int, unsigned char *, int, int *, unsigned long *,
                             void (*)(int, int, void *), void *);
int DSA_generate_key(DSA *);
DSA *DSA_new(void);
void DSA_free(DSA *);
int DSA_size(const DSA *);
int DSA_sign(int, const unsigned char *, int, unsigned char *, unsigned int *,
             DSA *);
int DSA_verify(int, const unsigned char *, int, const unsigned char *, int,
               DSA *);

/* added in 1.1.0 to access the opaque struct */
void DSA_get0_pqg(const DSA *, BIGNUM **, BIGNUM **, BIGNUM **);
int DSA_set0_pqg(DSA *, BIGNUM *, BIGNUM *, BIGNUM *);
void DSA_get0_key(const DSA *, BIGNUM **, BIGNUM **);
int DSA_set0_key(DSA *, BIGNUM *, BIGNUM *);
"""

MACROS = """
/* DSAparams_dup is a macro in 0.9.8 */
DSA *DSAparams_dup(DSA *);
int DSA_generate_parameters_ex(DSA *, int, unsigned char *, int,
                               int *, unsigned long *, BN_GENCB *);
"""

CUSTOMIZATIONS = """
/* These functions were added in OpenSSL 1.1.0-pre5 (beta2) */
#if OPENSSL_VERSION_NUMBER < 0x10100005 || defined(LIBRESSL_VERSION_NUMBER)
void DSA_get0_pqg(const DSA *d, BIGNUM **p, BIGNUM **q, BIGNUM **g)
{
    if (p != NULL)
        *p = d->p;
    if (q != NULL)
        *q = d->q;
    if (g != NULL)
        *g = d->g;
}
int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    /* If the fields in d are NULL, the corresponding input
     * parameters MUST be non-NULL.
     *
     * It is an error to give the results from get0 on d
     * as input parameters.
     */
    if (p == d->p || q == d->q || g == d->g)
        return 0;
    if (p != NULL) {
        BN_free(d->p);
        d->p = p;
    }
    if (q != NULL) {
        BN_free(d->q);
        d->q = q;
    }
    if (g != NULL) {
        BN_free(d->g);
        d->g = g;
    }
    return 1;
}
void DSA_get0_key(const DSA *d, BIGNUM **pub_key, BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = d->pub_key;
    if (priv_key != NULL)
        *priv_key = d->priv_key;
}
int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key)
{
    /* If the pub_key in d is NULL, the corresponding input
     * parameters MUST be non-NULL.  The priv_key field may
     * be left NULL.
     *
     * It is an error to give the results from get0 on d
     * as input parameters.
     */
    if (d->pub_key == pub_key
        || (d->priv_key != NULL && priv_key != d->priv_key))
        return 0;
    if (pub_key != NULL) {
        BN_free(d->pub_key);
        d->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(d->priv_key);
        d->priv_key = priv_key;
    }
    return 1;
}
#endif
"""
