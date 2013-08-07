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

INCLUDES = [
    '#include "openssl/evp.h"',
]

TYPES = [
    'static const int EVP_MAX_MD_SIZE;',
    'static const int EVP_MAX_KEY_LENGTH;',
    'static const int EVP_MAX_IV_LENGTH;',
    'static const int EVP_MAX_BLOCK_LENGTH;',
    'struct env_md_ctx_st { ...; };',
    'typedef ... EVP_MD;',
    'typedef struct env_md_ctx_st EVP_MD_CTX;',
]

FUNCTIONS = [
    'void EVP_cleanup(void);',
    'void EVP_MD_CTX_init(EVP_MD_CTX *ctx);',
    'EVP_MD_CTX *EVP_MD_CTX_create(void);',
    'int EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);',
    'int EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);',
    'int EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);',
    'int EVP_MD_CTX_cleanup(EVP_MD_CTX *ctx);',
    'void EVP_MD_CTX_destroy(EVP_MD_CTX *ctx);',
    'int EVP_MD_CTX_copy_ex(EVP_MD_CTX *out,const EVP_MD_CTX *in);',
    'int EVP_DigestInit(EVP_MD_CTX *ctx, const EVP_MD *type);',
    'int EVP_DigestFinal(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);',
    'int EVP_MD_CTX_copy(EVP_MD_CTX *out,EVP_MD_CTX *in);',
    'const EVP_MD *EVP_get_digestbyname(const char *name);',
    'const EVP_MD *EVP_get_digestbynid(int n);',
    'const EVP_MD *EVP_get_digestbyobj(const ASN1_OBJECT *o);',
    'const EVP_MD *EVP_md_null(void);',
    'const EVP_MD *EVP_md4(void);',
    'const EVP_MD *EVP_md5(void);',
    'const EVP_MD *EVP_sha(void);',
    'const EVP_MD *EVP_sha1(void);',
    'const EVP_MD *EVP_dss(void);',
    'const EVP_MD *EVP_dss1(void);',
    'const EVP_MD *EVP_ecdsa(void);',
    'const EVP_MD *EVP_sha224(void);',
    'const EVP_MD *EVP_sha256(void);',
    'const EVP_MD *EVP_sha384(void);',
    'const EVP_MD *EVP_sha512(void);',
    'const EVP_MD *EVP_ripemd160(void);',
    'int EVP_MD_type(const EVP_MD *md);',
    'int EVP_MD_pkey_type(const EVP_MD *md);',
    'int EVP_MD_size(const EVP_MD *md);',
    'int EVP_MD_block_size(const EVP_MD *md);',
    'const EVP_MD *EVP_MD_CTX_md(const EVP_MD_CTX *ctx);',
    'int EVP_MD_CTX_size(const EVP_MD_CTX *ctx);',
    'int EVP_MD_CTX_block_size(const EVP_MD_CTX *ctx);',
    'int EVP_MD_CTX_type(const EVP_MD_CTX *ctx);',
]
