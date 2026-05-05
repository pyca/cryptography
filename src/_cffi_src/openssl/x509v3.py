# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

import os

INCLUDES = """
#include <openssl/x509v3.h>
"""

USE_CONST_X509 = bool(os.environ.get("USE_CONST_X509"))

TYPES = f"""
typedef ... CONF;

typedef struct {{
    {"const X509" if USE_CONST_X509 else "X509"} *issuer_cert;
    {"const X509" if USE_CONST_X509 else "X509"} *subject_cert;
    ...;
}} X509V3_CTX;

static const int GEN_EMAIL;
static const int GEN_DNS;
static const int GEN_URI;

typedef ... GENERAL_NAMES;

/* Only include the one union element used by pyOpenSSL. */
typedef struct {{
    int type;
    union {{
        ASN1_IA5STRING *ia5;   /* rfc822Name, dNSName, */
                               /*   uniformResourceIdentifier */
    }} d;
    ...;
}} GENERAL_NAME;
"""

FUNCTIONS = """
void X509V3_set_ctx(X509V3_CTX *, X509 *, X509 *, X509_REQ *, X509_CRL *, int);
int GENERAL_NAME_print(BIO *, GENERAL_NAME *);
void GENERAL_NAMES_free(GENERAL_NAMES *);
void *X509V3_EXT_d2i(X509_EXTENSION *);
X509_EXTENSION *X509V3_EXT_nconf(CONF *, X509V3_CTX *, const char *,
                                 const char *);

void X509V3_set_ctx_nodb(X509V3_CTX *);

int sk_GENERAL_NAME_num(GENERAL_NAMES *);
GENERAL_NAME *sk_GENERAL_NAME_value(GENERAL_NAMES *, int);
"""

CUSTOMIZATIONS = """
"""
