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

INCLUDES = """
#include <openssl/rsa.h>
"""

TYPES = """
typedef struct rsa_st {
    BIGNUM *n;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *dmp1;
    BIGNUM *dmq1;
    BIGNUM *iqmp;
    ...;
} RSA;
typedef ... BN_GENCB;
static const int RSA_PKCS1_PADDING;
static const int RSA_SSLV23_PADDING;
static const int RSA_NO_PADDING;
static const int RSA_PKCS1_OAEP_PADDING;
static const int RSA_X931_PADDING;
static const int RSA_F4;
"""

FUNCTIONS = """
RSA *RSA_new(void);
void RSA_free(RSA *);
int RSA_size(const RSA *);
int RSA_generate_key_ex(RSA *, int, BIGNUM *, BN_GENCB *);
int RSA_check_key(const RSA *);
RSA *RSAPublicKey_dup(RSA *);
int RSA_public_encrypt(int, const unsigned char *, unsigned char *,
                       RSA *, int);
int RSA_private_encrypt(int, const unsigned char *, unsigned char *,
                        RSA *, int);
int RSA_public_decrypt(int, const unsigned char *, unsigned char *,
                       RSA *, int);
int RSA_private_decrypt(int, const unsigned char *, unsigned char *,
                        RSA *, int);
int RSA_print(BIO *, const RSA *, int);
"""

MACROS = """
int EVP_PKEY_CTX_set_rsa_padding(EVP_PKEY_CTX *, int);
int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *, int);
"""

CUSTOMIZATIONS = """
#if OPENSSL_VERSION_NUMBER < 0x10000000
// see evp.py for the definition of Cryptography_HAS_PKEY_CTX
int (*EVP_PKEY_CTX_set_rsa_padding)(EVP_PKEY_CTX *, int) = NULL;
int (*EVP_PKEY_CTX_set_rsa_pss_saltlen)(EVP_PKEY_CTX *, int) = NULL;
#endif
"""

CONDITIONAL_NAMES = {
    "Cryptography_HAS_PKEY_CTX": [
        "EVP_PKEY_CTX_set_rsa_padding",
        "EVP_PKEY_CTX_set_rsa_pss_saltlen",
    ]
}
