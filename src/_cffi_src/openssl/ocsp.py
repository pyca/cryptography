# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

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
"""

FUNCTIONS = """
int OCSP_response_status(OCSP_RESPONSE *);
OCSP_BASICRESP *OCSP_response_get1_basic(OCSP_RESPONSE *);
int OCSP_BASICRESP_get_ext_count(OCSP_BASICRESP *);
X509_EXTENSION *OCSP_BASICRESP_get_ext(OCSP_BASICRESP *, int);
int OCSP_resp_count(OCSP_BASICRESP *);
OCSP_SINGLERESP *OCSP_resp_get0(OCSP_BASICRESP *, int);
int OCSP_SINGLERESP_get_ext_count(OCSP_SINGLERESP *);
X509_EXTENSION *OCSP_SINGLERESP_get_ext(OCSP_SINGLERESP *, int);

int OCSP_single_get0_status(OCSP_SINGLERESP *, int *, ASN1_GENERALIZEDTIME **,
                            ASN1_GENERALIZEDTIME **, ASN1_GENERALIZEDTIME **);

int OCSP_request_onereq_count(OCSP_REQUEST *);
OCSP_ONEREQ *OCSP_request_onereq_get0(OCSP_REQUEST *, int);
int OCSP_ONEREQ_get_ext_count(OCSP_ONEREQ *);
X509_EXTENSION *OCSP_ONEREQ_get_ext(OCSP_ONEREQ *, int);
OCSP_CERTID *OCSP_onereq_get0_id(OCSP_ONEREQ *);


OCSP_BASICRESP *OCSP_BASICRESP_new(void);
void OCSP_BASICRESP_free(OCSP_BASICRESP *);
OCSP_SINGLERESP *OCSP_basic_add1_status(OCSP_BASICRESP *, OCSP_CERTID *, int,
                                        int, ASN1_TIME *, ASN1_TIME *,
                                        ASN1_TIME *);
int OCSP_basic_add1_nonce(OCSP_BASICRESP *, unsigned char *, int);
int OCSP_basic_add1_cert(OCSP_BASICRESP *, X509 *);
int OCSP_BASICRESP_add1_ext_i2d(OCSP_BASICRESP *, int, void *, int,
                                unsigned long);
int OCSP_basic_sign(OCSP_BASICRESP *, X509 *, EVP_PKEY *, const EVP_MD *,
                    Cryptography_STACK_OF_X509 *, unsigned long);
OCSP_RESPONSE *OCSP_response_create(int, OCSP_BASICRESP *);

OCSP_REQUEST *OCSP_REQUEST_new(void);
void OCSP_REQUEST_free(OCSP_REQUEST *);
int OCSP_request_add1_nonce(OCSP_REQUEST *, unsigned char *, int);
int OCSP_REQUEST_add1_ext_i2d(OCSP_REQUEST *, int, void *, int, unsigned long);
int OCSP_id_get0_info(ASN1_OCTET_STRING **, ASN1_OBJECT **,
                      ASN1_OCTET_STRING **, ASN1_INTEGER **, OCSP_CERTID *);
OCSP_REQUEST *d2i_OCSP_REQUEST_bio(BIO *, OCSP_REQUEST **);
OCSP_RESPONSE *d2i_OCSP_RESPONSE_bio(BIO *, OCSP_RESPONSE **);
int i2d_OCSP_REQUEST_bio(BIO *, OCSP_REQUEST *);
int i2d_OCSP_RESPONSE_bio(BIO *, OCSP_RESPONSE *);
"""

CUSTOMIZATIONS = """
"""
