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
#include <openssl/aes.h>
"""

TYPES = """
static const int Cryptography_HAS_AES_WRAP;

struct aes_key_st {
    ...;
};
typedef struct aes_key_st AES_KEY;
"""

FUNCTIONS = """
int AES_set_encrypt_key(const unsigned char *, const int, AES_KEY *);
int AES_set_decrypt_key(const unsigned char *, const int, AES_KEY *);
/* The ctr128_encrypt function is only useful in 0.9.8. You should use EVP for
   this in 1.0.0+. */
void AES_ctr128_encrypt(const unsigned char *, unsigned char *,
                        const unsigned long, const AES_KEY *,
                        unsigned char[], unsigned char[], unsigned int *);

"""

MACROS = """
/* these can be moved back to FUNCTIONS once we drop support for 0.9.8h.
   This should be when we drop RHEL/CentOS 5, which is on 0.9.8e. */
int AES_wrap_key(AES_KEY *, const unsigned char *, unsigned char *,
                 const unsigned char *, unsigned int);
int AES_unwrap_key(AES_KEY *, const unsigned char *, unsigned char *,
                   const unsigned char *, unsigned int);
"""

CUSTOMIZATIONS = """
// OpenSSL 0.9.8h+
#if OPENSSL_VERSION_NUMBER >= 0x0090808fL
static const long Cryptography_HAS_AES_WRAP = 1;
#else
static const long Cryptography_HAS_AES_WRAP = 0;
int (*AES_wrap_key)(AES_KEY *, const unsigned char *, unsigned char *,
                    const unsigned char *, unsigned int) = NULL;
int (*AES_unwrap_key)(AES_KEY *, const unsigned char *, unsigned char *,
                      const unsigned char *, unsigned int) = NULL;
#endif

"""

CONDITIONAL_NAMES = {
    "Cryptography_HAS_AES_WRAP": [
        "AES_wrap_key",
        "AES_unwrap_key",
    ],
}
