# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/ocsp.h>
"""

TYPES = """
typedef ... OCSP_REQUEST;
typedef ... OCSP_ONEREQ;
typedef ... OCSP_RESPONSE;
typedef ... OCSP_BASICRESP;
typedef ... OCSP_SINGLERESP;
typedef ... OCSP_CERTID;
static const long OCSP_NOCERTS;
static const long OCSP_RESPID_KEY;
"""

FUNCTIONS = """
OCSP_ONEREQ *OCSP_request_add0_id(OCSP_REQUEST *, OCSP_CERTID *);
OCSP_CERTID *OCSP_cert_to_id(const EVP_MD *, const X509 *, const X509 *);
void OCSP_CERTID_free(OCSP_CERTID *);


OCSP_BASICRESP *OCSP_BASICRESP_new(void);
void OCSP_BASICRESP_free(OCSP_BASICRESP *);
OCSP_SINGLERESP *OCSP_basic_add1_status(OCSP_BASICRESP *, OCSP_CERTID *, int,
                                        int, ASN1_TIME *, ASN1_TIME *,
                                        ASN1_TIME *);
int OCSP_basic_add1_cert(OCSP_BASICRESP *, X509 *);
int OCSP_BASICRESP_add_ext(OCSP_BASICRESP *, X509_EXTENSION *, int);
int OCSP_basic_sign(OCSP_BASICRESP *, X509 *, EVP_PKEY *, const EVP_MD *,
                    Cryptography_STACK_OF_X509 *, unsigned long);
OCSP_RESPONSE *OCSP_response_create(int, OCSP_BASICRESP *);
void OCSP_RESPONSE_free(OCSP_RESPONSE *);

OCSP_REQUEST *OCSP_REQUEST_new(void);
void OCSP_REQUEST_free(OCSP_REQUEST *);
int OCSP_REQUEST_add_ext(OCSP_REQUEST *, X509_EXTENSION *, int);
int i2d_OCSP_REQUEST_bio(BIO *, OCSP_REQUEST *);
int i2d_OCSP_RESPONSE_bio(BIO *, OCSP_RESPONSE *);
"""

CUSTOMIZATIONS = """
"""
