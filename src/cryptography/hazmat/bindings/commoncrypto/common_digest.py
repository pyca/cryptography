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
#include <CommonCrypto/CommonDigest.h>
"""

TYPES = """
typedef uint32_t CC_LONG;
typedef uint64_t CC_LONG64;
typedef struct CC_MD5state_st {
    ...;
} CC_MD5_CTX;
typedef struct CC_SHA1state_st {
    ...;
} CC_SHA1_CTX;
typedef struct CC_SHA256state_st {
    ...;
} CC_SHA256_CTX;
typedef struct CC_SHA512state_st {
    ...;
} CC_SHA512_CTX;
"""

FUNCTIONS = """
int CC_MD5_Init(CC_MD5_CTX *);
int CC_MD5_Update(CC_MD5_CTX *, const void *, CC_LONG);
int CC_MD5_Final(unsigned char *, CC_MD5_CTX *);

int CC_SHA1_Init(CC_SHA1_CTX *);
int CC_SHA1_Update(CC_SHA1_CTX *, const void *, CC_LONG);
int CC_SHA1_Final(unsigned char *, CC_SHA1_CTX *);

int CC_SHA224_Init(CC_SHA256_CTX *);
int CC_SHA224_Update(CC_SHA256_CTX *, const void *, CC_LONG);
int CC_SHA224_Final(unsigned char *, CC_SHA256_CTX *);

int CC_SHA256_Init(CC_SHA256_CTX *);
int CC_SHA256_Update(CC_SHA256_CTX *, const void *, CC_LONG);
int CC_SHA256_Final(unsigned char *, CC_SHA256_CTX *);

int CC_SHA384_Init(CC_SHA512_CTX *);
int CC_SHA384_Update(CC_SHA512_CTX *, const void *, CC_LONG);
int CC_SHA384_Final(unsigned char *, CC_SHA512_CTX *);

int CC_SHA512_Init(CC_SHA512_CTX *);
int CC_SHA512_Update(CC_SHA512_CTX *, const void *, CC_LONG);
int CC_SHA512_Final(unsigned char *, CC_SHA512_CTX *);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
