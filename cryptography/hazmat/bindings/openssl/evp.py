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
#include <openssl/evp.h>
"""

TYPES = """
typedef struct {
    ...;
} EVP_CIPHER_CTX;
typedef ... EVP_CIPHER;
typedef ... EVP_MD;
typedef struct env_md_ctx_st EVP_MD_CTX;

typedef struct evp_pkey_st {
    int type;
    ...;
} EVP_PKEY;
static const int EVP_PKEY_RSA;
static const int EVP_PKEY_DSA;
static const int Cryptography_EVP_CTRL_GCM_SET_IVLEN;
static const int Cryptography_EVP_CTRL_GCM_GET_TAG;
static const int Cryptography_EVP_CTRL_GCM_SET_TAG;
"""

FUNCTIONS = """
void OpenSSL_add_all_algorithms();

const EVP_CIPHER *EVP_get_cipherbyname(const char *);
int EVP_EncryptInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                       const unsigned char *, const unsigned char *);
int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *, int);
int EVP_EncryptUpdate(EVP_CIPHER_CTX *, unsigned char *, int *,
                      const unsigned char *, int);
int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *);
int EVP_DecryptInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                       const unsigned char *, const unsigned char *);
int EVP_DecryptUpdate(EVP_CIPHER_CTX *, unsigned char *, int *,
                      const unsigned char *, int);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *);
int EVP_CipherInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                      const unsigned char *, const unsigned char *, int);
int EVP_CipherUpdate(EVP_CIPHER_CTX *, unsigned char *, int *,
                     const unsigned char *, int);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *);
int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *);
const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *);
int EVP_CIPHER_block_size(const EVP_CIPHER *);
void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new();
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *, int);

EVP_MD_CTX *EVP_MD_CTX_create();
int EVP_MD_CTX_copy_ex(EVP_MD_CTX *, const EVP_MD_CTX *);
int EVP_DigestInit_ex(EVP_MD_CTX *, const EVP_MD *, ENGINE *);
int EVP_DigestUpdate(EVP_MD_CTX *, const void *, size_t);
int EVP_DigestFinal_ex(EVP_MD_CTX *, unsigned char *, unsigned int *);
int EVP_MD_CTX_cleanup(EVP_MD_CTX *);
void EVP_MD_CTX_destroy(EVP_MD_CTX *);
const EVP_MD *EVP_get_digestbyname(const char *);
const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *);
int EVP_MD_size(const EVP_MD *);

EVP_PKEY *EVP_PKEY_new();
void EVP_PKEY_free(EVP_PKEY *);
int EVP_PKEY_type(int);
int EVP_PKEY_bits(EVP_PKEY *);
RSA *EVP_PKEY_get1_RSA(EVP_PKEY *);

int EVP_SignInit(EVP_MD_CTX *, const EVP_MD *);
int EVP_SignUpdate(EVP_MD_CTX *, const void *, size_t);
int EVP_SignFinal(EVP_MD_CTX *, unsigned char *, unsigned int *, EVP_PKEY *);

int EVP_VerifyInit(EVP_MD_CTX *, const EVP_MD *);
int EVP_VerifyUpdate(EVP_MD_CTX *, const void *, size_t);
int EVP_VerifyFinal(EVP_MD_CTX *, const unsigned char *, unsigned int,
                    EVP_PKEY *);
"""

MACROS = """
int EVP_PKEY_assign_RSA(EVP_PKEY *, RSA *);
int EVP_PKEY_assign_DSA(EVP_PKEY *, DSA *);
int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *, int, int, void *);
"""

CUSTOMIZATIONS = """
#ifdef EVP_CTRL_GCM_SET_TAG
const int Cryptography_EVP_CTRL_GCM_GET_TAG = EVP_CTRL_GCM_GET_TAG;
const int Cryptography_EVP_CTRL_GCM_SET_TAG = EVP_CTRL_GCM_SET_TAG;
const int Cryptography_EVP_CTRL_GCM_SET_IVLEN = EVP_CTRL_GCM_SET_IVLEN;
#else
const int Cryptography_EVP_CTRL_GCM_GET_TAG = -1;
const int Cryptography_EVP_CTRL_GCM_SET_TAG = -1;
const int Cryptography_EVP_CTRL_GCM_SET_IVLEN = -1;
#endif
"""
