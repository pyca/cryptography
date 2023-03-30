# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/x509v3.h>

/*
 * This is part of a work-around for the difficulty cffi has in dealing with
 * `STACK_OF(foo)` as the name of a type.  We invent a new, simpler name that
 * will be an alias for this type and use the alias throughout.  This works
 * together with another opaque typedef for the same name in the TYPES section.
 * Note that the result is an opaque type.
 */
"""

TYPES = """
typedef ... EXTENDED_KEY_USAGE;
typedef ... CONF;

typedef struct {
    X509 *issuer_cert;
    X509 *subject_cert;
    ...;
} X509V3_CTX;

static const int GEN_EMAIL;
static const int GEN_DNS;
static const int GEN_URI;

typedef struct stack_st_GENERAL_NAME GENERAL_NAMES;

/* Only include the one union element used by pyOpenSSL. */
typedef struct {
    int type;
    union {
        ASN1_IA5STRING *ia5;   /* rfc822Name, dNSName, */
                               /*   uniformResourceIdentifier */
    } d;
    ...;
} GENERAL_NAME;
"""


FUNCTIONS = """
void X509V3_set_ctx(X509V3_CTX *, X509 *, X509 *, X509_REQ *, X509_CRL *, int);
int GENERAL_NAME_print(BIO *, GENERAL_NAME *);
void GENERAL_NAMES_free(GENERAL_NAMES *);
void *X509V3_EXT_d2i(X509_EXTENSION *);
X509_EXTENSION *X509V3_EXT_nconf(CONF *, X509V3_CTX *, const char *,
                                 const char *);

void X509V3_set_ctx_nodb(X509V3_CTX *);

int sk_GENERAL_NAME_num(struct stack_st_GENERAL_NAME *);
GENERAL_NAME *sk_GENERAL_NAME_value(struct stack_st_GENERAL_NAME *, int);
"""

CUSTOMIZATIONS = """
"""
