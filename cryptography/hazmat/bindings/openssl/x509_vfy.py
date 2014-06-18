# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

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
"""

TYPES = """
static const long Cryptography_HAS_X509_VERIFY_PARAM_SET_HOSTFLAGS;
static const long Cryptography_HAS_102_VERIFICATION_PARAMS;
static const long Cryptography_HAS_X509_V_FLAG_TRUSTED_FIRST;
static const long Cryptography_HAS_100_VERIFICATION_PARAMS;
static const long Cryptography_HAS_X509_V_FLAG_CHECK_SS_SIGNATURE;

typedef ... Cryptography_STACK_OF_ASN1_OBJECT;
typedef ... X509_VERIFY_PARAM;

/* While these are defined in the source as ints, they're tagged here
   as longs, just in case they ever grow to large, such as what we saw
   with OP_ALL. */
static const long X509_V_FLAG_CB_ISSUER_CHECK;
static const long X509_V_FLAG_USE_CHECK_TIME;
static const long X509_V_FLAG_CRL_CHECK;
static const long X509_V_FLAG_CRL_CHECK_ALL;
static const long X509_V_FLAG_IGNORE_CRITICAL;
static const long X509_V_FLAG_X509_STRICT;
static const long X509_V_FLAG_ALLOW_PROXY_CERTS;
static const long X509_V_FLAG_POLICY_CHECK;
static const long X509_V_FLAG_EXPLICIT_POLICY;
static const long X509_V_FLAG_INHIBIT_ANY;
static const long X509_V_FLAG_INHIBIT_MAP;
static const long X509_V_FLAG_NOTIFY_POLICY;
static const long X509_V_FLAG_EXTENDED_CRL_SUPPORT;
static const long X509_V_FLAG_USE_DELTAS;
static const long X509_V_FLAG_CHECK_SS_SIGNATURE;
static const long X509_V_FLAG_TRUSTED_FIRST;
static const long X509_V_FLAG_SUITEB_128_LOS_ONLY;
static const long X509_V_FLAG_SUITEB_192_LOS;
static const long X509_V_FLAG_SUITEB_128_LOS;
static const long X509_V_FLAG_PARTIAL_CHAIN;
"""

FUNCTIONS = """
X509_VERIFY_PARAM *X509_VERIFY_PARAM_new(void);
int X509_VERIFY_PARAM_set_flags(X509_VERIFY_PARAM *, unsigned long);
int X509_VERIFY_PARAM_clear_flags(X509_VERIFY_PARAM *, unsigned long);
unsigned long X509_VERIFY_PARAM_get_flags(X509_VERIFY_PARAM *);
int X509_VERIFY_PARAM_set_purpose(X509_VERIFY_PARAM *, int);
int X509_VERIFY_PARAM_set_trust(X509_VERIFY_PARAM *, int);
void X509_VERIFY_PARAM_set_time(X509_VERIFY_PARAM *, time_t);
int X509_VERIFY_PARAM_add0_policy(X509_VERIFY_PARAM *, ASN1_OBJECT *);
int X509_VERIFY_PARAM_set1_policies(X509_VERIFY_PARAM *,
                                    Cryptography_STACK_OF_ASN1_OBJECT *);
void X509_VERIFY_PARAM_set_depth(X509_VERIFY_PARAM *, int);
int X509_VERIFY_PARAM_get_depth(const X509_VERIFY_PARAM *);
"""

MACROS = """
int X509_VERIFY_PARAM_set1_host(X509_VERIFY_PARAM *, const unsigned char *,
                                size_t);
void X509_VERIFY_PARAM_set_hostflags(X509_VERIFY_PARAM *, unsigned int);
int X509_VERIFY_PARAM_set1_email(X509_VERIFY_PARAM *, const unsigned char *,
                                 size_t);
int X509_VERIFY_PARAM_set1_ip(X509_VERIFY_PARAM *, const unsigned char *,
                              size_t);
int X509_VERIFY_PARAM_set1_ip_asc(X509_VERIFY_PARAM *, const char *);
"""

CUSTOMIZATIONS = """
// OpenSSL 1.0.2+, but only some very new releases
#ifdef X509_VERIFY_PARAM_set_hostflags
static const long Cryptography_HAS_X509_VERIFY_PARAM_SET_HOSTFLAGS = 1;
#else
static const long Cryptography_HAS_X509_VERIFY_PARAM_SET_HOSTFLAGS = 0;
void (*X509_VERIFY_PARAM_set_hostflags)(X509_VERIFY_PARAM *,
                                        unsigned int) = NULL;
#endif

// OpenSSL 1.0.2+
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
static const long Cryptography_HAS_102_VERIFICATION_PARAMS = 1;
#else
static const long Cryptography_HAS_102_VERIFICATION_PARAMS = 0;
// X509_V_FLAG_TRUSTED_FIRST is also new in 1.0.2, but added separately below
static const long X509_V_FLAG_SUITEB_128_LOS_ONLY = 0;
static const long X509_V_FLAG_SUITEB_192_LOS = 0;
static const long X509_V_FLAG_SUITEB_128_LOS = 0;
static const long X509_V_FLAG_PARTIAL_CHAIN = 0;

int (*X509_VERIFY_PARAM_set1_host)(X509_VERIFY_PARAM *, const unsigned char *,
                                   size_t) = NULL;
int (*X509_VERIFY_PARAM_set1_email)(X509_VERIFY_PARAM *, const unsigned char *,
                                    size_t) = NULL;
int (*X509_VERIFY_PARAM_set1_ip)(X509_VERIFY_PARAM *, const unsigned char *,
                                 size_t) = NULL;
int (*X509_VERIFY_PARAM_set1_ip_asc)(X509_VERIFY_PARAM *, const char *) = NULL;
#endif

// OpenSSL 1.0.2+, *or* Fedora 20's flavor of OpenSSL 1.0.1e...
#ifdef X509_V_FLAG_TRUSTED_FIRST
static const long Cryptography_HAS_X509_V_FLAG_TRUSTED_FIRST = 1;
#else
static const long Cryptography_HAS_X509_V_FLAG_TRUSTED_FIRST = 0;
static const long X509_V_FLAG_TRUSTED_FIRST = 0;
#endif

// OpenSSL 1.0.0+
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
static const long Cryptography_HAS_100_VERIFICATION_PARAMS = 1;
#else
static const long Cryptography_HAS_100_VERIFICATION_PARAMS = 0;
static const long X509_V_FLAG_EXTENDED_CRL_SUPPORT = 0;
static const long X509_V_FLAG_USE_DELTAS = 0;
#endif

// OpenSSL 0.9.8recent+
#ifdef X509_V_FLAG_CHECK_SS_SIGNATURE
static const long Cryptography_HAS_X509_V_FLAG_CHECK_SS_SIGNATURE = 1;
#else
static const long Cryptography_HAS_X509_V_FLAG_CHECK_SS_SIGNATURE = 0;
static const long X509_V_FLAG_CHECK_SS_SIGNATURE = 0;
#endif
"""

CONDITIONAL_NAMES = {
    "Cryptography_HAS_X509_VERIFY_PARAM_SET_HOSTFLAGS": [
        "X509_VERIFY_PARAM_set_hostflags",
    ],
    "Cryptography_HAS_102_VERIFICATION_PARAMS": [
        "X509_V_FLAG_SUITEB_128_LOS_ONLY",
        "X509_V_FLAG_SUITEB_192_LOS",
        "X509_V_FLAG_SUITEB_128_LOS",
        "X509_V_FLAG_PARTIAL_CHAIN",

        "X509_VERIFY_PARAM_set1_host",
        "X509_VERIFY_PARAM_set1_email",
        "X509_VERIFY_PARAM_set1_ip",
        "X509_VERIFY_PARAM_set1_ip_asc",
    ],
    "Cryptography_HAS_X509_V_FLAG_TRUSTED_FIRST": [
        "X509_V_FLAG_TRUSTED_FIRST",
    ],
    "Cryptography_HAS_100_VERIFICATION_PARAMS": [
        "Cryptography_HAS_100_VERIFICATION_PARAMS",
        "X509_V_FLAG_EXTENDED_CRL_SUPPORT",
        "X509_V_FLAG_USE_DELTAS",
    ],
    "Cryptography_HAS_X509_V_FLAG_CHECK_SS_SIGNATURE": [
        "X509_V_FLAG_CHECK_SS_SIGNATURE",
    ]
}
