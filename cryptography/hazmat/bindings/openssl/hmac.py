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
#include <openssl/hmac.h>
"""

TYPES = """
typedef struct { ...; } HMAC_CTX;
"""

FUNCTIONS = """
void HMAC_CTX_init(HMAC_CTX *);
void HMAC_CTX_cleanup(HMAC_CTX *);

int Cryptography_HMAC_Init_ex(HMAC_CTX *, const void *, int, const EVP_MD *,
                              ENGINE *);
int Cryptography_HMAC_Update(HMAC_CTX *, const unsigned char *, size_t);
int Cryptography_HMAC_Final(HMAC_CTX *, unsigned char *, unsigned int *);
int HMAC_CTX_copy(HMAC_CTX *, HMAC_CTX *);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
int Cryptography_HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int key_len,
                              const EVP_MD *md, ENGINE *impl) {
#if OPENSSL_VERSION_NUMBER >= 0x010000000
    return HMAC_Init_ex(ctx, key, key_len, md, impl);
#else
    HMAC_Init_ex(ctx, key, key_len, md, impl);
    return 1;
#endif
}

int Cryptography_HMAC_Update(HMAC_CTX *ctx, const unsigned char *data,
                             size_t data_len) {
#if OPENSSL_VERSION_NUMBER >= 0x010000000
    return HMAC_Update(ctx, data, data_len);
#else
    HMAC_Update(ctx, data, data_len);
    return 1;
#endif
}

int Cryptography_HMAC_Final(HMAC_CTX *ctx, unsigned char *digest,
    unsigned int *digest_len) {
#if OPENSSL_VERSION_NUMBER >= 0x010000000
    return HMAC_Final(ctx, digest, digest_len);
#else
    HMAC_Final(ctx, digest, digest_len);
    return 1;
#endif
}

"""
