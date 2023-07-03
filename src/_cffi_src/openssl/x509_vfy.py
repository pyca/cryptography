# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/x509_vfy.h>

/*
 * This is part of a work-around for the difficulty cffi has in dealing with
 * `STACK_OF(foo)` as the name of a type.  We invent a new, simpler name that
 * will be an alias for this type and use the alias throughout.  This works
 * together with another opaque typedef for the same name in the TYPES section.
 * Note that the result is an opaque type.
 */
typedef STACK_OF(ASN1_OBJECT) Cryptography_STACK_OF_ASN1_OBJECT;
typedef STACK_OF(X509_OBJECT) Cryptography_STACK_OF_X509_OBJECT;
"""

TYPES = """
static const long Cryptography_HAS_X509_STORE_CTX_GET_ISSUER;

typedef ... Cryptography_STACK_OF_ASN1_OBJECT;
typedef ... Cryptography_STACK_OF_X509_OBJECT;

typedef ... X509_OBJECT;
typedef ... X509_STORE;
typedef ... X509_VERIFY_PARAM;
typedef ... X509_STORE_CTX;

typedef int (*X509_STORE_CTX_get_issuer_fn)(X509 **, X509_STORE_CTX *, X509 *);

static const int X509_V_OK;
static const int X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT;
static const int X509_V_ERR_UNABLE_TO_GET_CRL;
static const int X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE;
static const int X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE;
static const int X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY;
static const int X509_V_ERR_CERT_SIGNATURE_FAILURE;
static const int X509_V_ERR_CRL_SIGNATURE_FAILURE;
static const int X509_V_ERR_CERT_NOT_YET_VALID;
static const int X509_V_ERR_CERT_HAS_EXPIRED;
static const int X509_V_ERR_CRL_NOT_YET_VALID;
static const int X509_V_ERR_CRL_HAS_EXPIRED;
static const int X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD;
static const int X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD;
static const int X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD;
static const int X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD;
static const int X509_V_ERR_OUT_OF_MEM;
static const int X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT;
static const int X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN;
static const int X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY;
static const int X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE;
static const int X509_V_ERR_CERT_CHAIN_TOO_LONG;
static const int X509_V_ERR_CERT_REVOKED;
static const int X509_V_ERR_INVALID_CA;
static const int X509_V_ERR_PATH_LENGTH_EXCEEDED;
static const int X509_V_ERR_INVALID_PURPOSE;
static const int X509_V_ERR_CERT_UNTRUSTED;
static const int X509_V_ERR_CERT_REJECTED;
static const int X509_V_ERR_SUBJECT_ISSUER_MISMATCH;
static const int X509_V_ERR_AKID_SKID_MISMATCH;
static const int X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH;
static const int X509_V_ERR_KEYUSAGE_NO_CERTSIGN;
static const int X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER;
static const int X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION;
static const int X509_V_ERR_KEYUSAGE_NO_CRL_SIGN;
static const int X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION;
static const int X509_V_ERR_INVALID_NON_CA;
static const int X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED;
static const int X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE;
static const int X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED;
static const int X509_V_ERR_INVALID_EXTENSION;
static const int X509_V_ERR_INVALID_POLICY_EXTENSION;
static const int X509_V_ERR_NO_EXPLICIT_POLICY;
static const int X509_V_ERR_DIFFERENT_CRL_SCOPE;
static const int X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE;
static const int X509_V_ERR_UNNESTED_RESOURCE;
static const int X509_V_ERR_PERMITTED_VIOLATION;
static const int X509_V_ERR_EXCLUDED_VIOLATION;
static const int X509_V_ERR_SUBTREE_MINMAX;
static const int X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE;
static const int X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX;
static const int X509_V_ERR_UNSUPPORTED_NAME_SYNTAX;
static const int X509_V_ERR_CRL_PATH_VALIDATION_ERROR;
static const int X509_V_ERR_HOSTNAME_MISMATCH;
static const int X509_V_ERR_EMAIL_MISMATCH;
static const int X509_V_ERR_IP_ADDRESS_MISMATCH;
static const int X509_V_ERR_APPLICATION_VERIFICATION;


/* While these are defined in the source as ints, they're tagged here
   as longs, just in case they ever grow to large, such as what we saw
   with OP_ALL. */

/* Verification parameters */
static const long X509_V_FLAG_CRL_CHECK;
static const long X509_V_FLAG_CRL_CHECK_ALL;
static const long X509_V_FLAG_IGNORE_CRITICAL;
static const long X509_V_FLAG_X509_STRICT;
static const long X509_V_FLAG_ALLOW_PROXY_CERTS;
static const long X509_V_FLAG_POLICY_CHECK;
static const long X509_V_FLAG_EXPLICIT_POLICY;
static const long X509_V_FLAG_INHIBIT_MAP;
static const long X509_V_FLAG_CHECK_SS_SIGNATURE;
static const long X509_V_FLAG_PARTIAL_CHAIN;

static const long X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT;
static const long X509_CHECK_FLAG_NO_WILDCARDS;
static const long X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS;
static const long X509_CHECK_FLAG_MULTI_LABEL_WILDCARDS;
static const long X509_CHECK_FLAG_SINGLE_LABEL_SUBDOMAINS;
static const long X509_CHECK_FLAG_NEVER_CHECK_SUBJECT;

/* Included due to external consumer, see
   https://github.com/pyca/pyopenssl/issues/1031 */
static const long X509_PURPOSE_SSL_CLIENT;
static const long X509_PURPOSE_SSL_SERVER;
static const long X509_PURPOSE_NS_SSL_SERVER;
static const long X509_PURPOSE_SMIME_SIGN;
static const long X509_PURPOSE_SMIME_ENCRYPT;
static const long X509_PURPOSE_CRL_SIGN;
static const long X509_PURPOSE_ANY;
static const long X509_PURPOSE_OCSP_HELPER;
static const long X509_PURPOSE_TIMESTAMP_SIGN;
static const long X509_PURPOSE_MIN;
static const long X509_PURPOSE_MAX;
"""

FUNCTIONS = """
int X509_verify_cert(X509_STORE_CTX *);

/* X509_STORE */
X509_STORE *X509_STORE_new(void);
int X509_STORE_add_cert(X509_STORE *, X509 *);
int X509_STORE_add_crl(X509_STORE *, X509_CRL *);
int X509_STORE_load_locations(X509_STORE *, const char *, const char *);
int X509_STORE_set1_param(X509_STORE *, X509_VERIFY_PARAM *);
int X509_STORE_set_default_paths(X509_STORE *);
int X509_STORE_set_flags(X509_STORE *, unsigned long);
/* Included due to external consumer, see
   https://github.com/pyca/pyopenssl/issues/1031 */
int X509_STORE_set_purpose(X509_STORE *, int);
int X509_STORE_up_ref(X509_STORE *);
void X509_STORE_free(X509_STORE *);

/* X509_STORE_CTX */
X509_STORE_CTX *X509_STORE_CTX_new(void);
void X509_STORE_CTX_cleanup(X509_STORE_CTX *);
void X509_STORE_CTX_free(X509_STORE_CTX *);
int X509_STORE_CTX_init(X509_STORE_CTX *, X509_STORE *, X509 *,
                        Cryptography_STACK_OF_X509 *);
Cryptography_STACK_OF_X509 *X509_STORE_CTX_get1_chain(X509_STORE_CTX *);
int X509_STORE_CTX_get_error(X509_STORE_CTX *);
void X509_STORE_CTX_set_error(X509_STORE_CTX *, int);
int X509_STORE_CTX_get_error_depth(X509_STORE_CTX *);
X509 *X509_STORE_CTX_get_current_cert(X509_STORE_CTX *);
void *X509_STORE_CTX_get_ex_data(X509_STORE_CTX *, int);

/* X509_VERIFY_PARAM */
X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void);
int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *, unsigned long);
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *, time_t);
void X509_VERIFY_PARAM_free(X509_VERIFY_PARAM *);

int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *, const char *,
                                size_t);
void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM *, unsigned int);
int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM *, const unsigned char *,
                              size_t);

int sk_X509_OBJECT_num(Cryptography_STACK_OF_X509_OBJECT *);
Cryptography_STACK_OF_X509_OBJECT *X509_STORE_get0_objects(X509_STORE *);

X509 *X509_STORE_CTX_get0_cert(X509_STORE_CTX *);
void X509_STORE_set_get_issuer(X509_STORE *, X509_STORE_CTX_get_issuer_fn);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_X509_STORE_CTX_GET_ISSUER = 0;
typedef void *X509_STORE_CTX_get_issuer_fn;
void (*X509_STORE_set_get_issuer)(X509_STORE *,
                                  X509_STORE_CTX_get_issuer_fn) = NULL;
#else
static const long Cryptography_HAS_X509_STORE_CTX_GET_ISSUER = 1;
#endif
"""
