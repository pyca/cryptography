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
#include <openssl/aes.h>
"""

TYPES = """
struct aes_key_st {
    ...;
};
typedef struct aes_key_st AES_KEY;
"""

FUNCTIONS = """
int AES_set_encrypt_key(const unsigned char *, const int, AES_KEY *);
int AES_set_decrypt_key(const unsigned char *, const int, AES_KEY *);
int AES_wrap_key(AES_KEY *, const unsigned char *, unsigned char *,
                 const unsigned char *, unsigned int);
int AES_unwrap_key(AES_KEY *, const unsigned char *, unsigned char *,
                   const unsigned char *, unsigned int);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
