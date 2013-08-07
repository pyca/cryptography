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

FUNCTIONS = [
    'int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,'
        'const unsigned char *salt, int saltlen, int iter,'
        'int keylen, unsigned char *out);',
    'int EVP_BytesToKey(const EVP_CIPHER *type,const EVP_MD *md,'
        'const unsigned char *salt,'
        'const unsigned char *data, int datal, int count,'
        'unsigned char *key,unsigned char *iv);',
]
