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
    '#include <openssl/bio.h>',
]

TYPES = [
    'static const int BIO_TYPE_NULL_FILTER;',
    'static const int BIO_TYPE_SSL;',
    'static const int BIO_TYPE_MD;',
    'static const int BIO_TYPE_BUFFER;',
    'static const int BIO_TYPE_CIPHER;',
    'static const int BIO_TYPE_BASE64;',
    'static const int BIO_TYPE_FILTER;',
]

FUNCTIONS = [
    # BIO null
    'BIO_METHOD *BIO_f_null(void);',
    # BIO ssl
    # TODO
    # BIO message digests
    'BIO_METHOD *BIO_f_md(void);',
    'int BIO_set_md(BIO *b, EVP_MD *md);',
    'int BIO_get_md(BIO *b, EVP_MD **mdp);',
    'int BIO_set_md_ctx(BIO *b, EVP_MD_CTX **mdcp);',
    'int BIO_get_md_ctx(BIO *b, EVP_MD_CTX **mdcp);',
    # BIO buffer
    'BIO_METHOD * BIO_f_buffer(void);',
    'long BIO_get_buffer_num_lines(BIO *b);',
    'long BIO_set_read_buffer_size(BIO *b, long size);',
    'long BIO_set_write_buffer_size(BIO *b, long size);',
    'long BIO_set_buffer_size(BIO *b, long size);',
    'long BIO_set_buffer_read_data(BIO *b, void *buf, long num);',
    # BIO cipher
    'BIO_METHOD *   BIO_f_cipher(void);',
    'void BIO_set_cipher(BIO *b,const EVP_CIPHER *cipher, unsigned char *key, unsigned char *iv, int enc);',
    'int BIO_get_cipher_status(BIO *b);',
    'int BIO_get_cipher_ctx(BIO *b, EVP_CIPHER_CTX **pctx);',
    # BIO base64
    'BIO_METHOD *BIO_f_base64(void);',
    # BIO zlib
]
