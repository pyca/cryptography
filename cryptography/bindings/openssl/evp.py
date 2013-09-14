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
    typedef struct { ...; } EVP_CIPHER_CTX;
    typedef ... EVP_CIPHER;
    typedef ... ENGINE;
"""

FUNCTIONS = """
    void OpenSSL_add_all_algorithms();
    const EVP_CIPHER *EVP_get_cipherbyname(const char *);
    int EVP_EncryptInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *,
                           ENGINE *, unsigned char *, unsigned char *);
    int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *, int);
    int EVP_EncryptUpdate(EVP_CIPHER_CTX *, unsigned char *, int *,
                          unsigned char *, int);
    int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *);
    int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *);
    const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *);
    int EVP_CIPHER_block_size(const EVP_CIPHER *);
"""
