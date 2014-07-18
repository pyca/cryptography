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
int Cryptography_HMAC_CTX_copy(HMAC_CTX *, HMAC_CTX *);
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
    unsigned int *outlen) {
#if OPENSSL_VERSION_NUMBER >= 0x010000000
    return HMAC_Final(ctx, digest, outlen);
#else
    HMAC_Final(ctx, digest, outlen);
    return 1;
#endif
}

int Cryptography_HMAC_CTX_copy(HMAC_CTX *dst_ctx, HMAC_CTX *src_ctx) {
#if OPENSSL_VERSION_NUMBER >= 0x010000000
    return HMAC_CTX_copy(dst_ctx, src_ctx);
#else
    HMAC_CTX_init(dst_ctx);
    if (!EVP_MD_CTX_copy_ex(&dst_ctx->i_ctx, &src_ctx->i_ctx)) {
        goto err;
    }
    if (!EVP_MD_CTX_copy_ex(&dst_ctx->o_ctx, &src_ctx->o_ctx)) {
        goto err;
    }
    if (!EVP_MD_CTX_copy_ex(&dst_ctx->md_ctx, &src_ctx->md_ctx)) {
        goto err;
    }
    memcpy(dst_ctx->key, src_ctx->key, HMAC_MAX_MD_CBLOCK);
    dst_ctx->key_length = src_ctx->key_length;
    dst_ctx->md = src_ctx->md;
    return 1;

    err:
        return 0;
#endif
}
"""

CONDITIONAL_NAMES = {}
