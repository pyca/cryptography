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
#if OPENSSL_VERSION_NUMBER >= 0x10001000L
#include <openssl/cmac.h>
#endif
"""

TYPES = """
static const int Cryptography_HAS_CMAC;
typedef ... CMAC_CTX;
"""

FUNCTIONS = """
"""

MACROS = """
CMAC_CTX *CMAC_CTX_new(void);
int CMAC_Init(CMAC_CTX *, const void *, size_t, const EVP_CIPHER *, ENGINE *);
int CMAC_Update(CMAC_CTX *, const void *, size_t);
int CMAC_Final(CMAC_CTX *, unsigned char *, size_t *);
int CMAC_CTX_copy(CMAC_CTX *, const CMAC_CTX *);
void CMAC_CTX_free(CMAC_CTX *);
"""

CUSTOMIZATIONS = """
#if OPENSSL_VERSION_NUMBER < 0x10001000L

static const long Cryptography_HAS_CMAC = 0;
typedef void CMAC_CTX;
CMAC_CTX *(*CMAC_CTX_new)(void) = NULL;
int (*CMAC_Init)(CMAC_CTX *, const void *, size_t, const EVP_CIPHER *,
    ENGINE *) = NULL;
int (*CMAC_Update)(CMAC_CTX *, const void *, size_t) = NULL;
int (*CMAC_Final)(CMAC_CTX *, unsigned char *, size_t *) = NULL;
int (*CMAC_CTX_copy)(CMAC_CTX *, const CMAC_CTX *) = NULL;
void (*CMAC_CTX_free)(CMAC_CTX *) = NULL;
#else
static const long Cryptography_HAS_CMAC = 1;
#endif
"""

CONDITIONAL_NAMES = {
    "Cryptography_HAS_CMAC": [
        "CMAC_CTX_new",
        "CMAC_Init",
        "CMAC_Update",
        "CMAC_Final",
        "CMAC_CTX_copy",
        "CMAC_CTX_free",
    ],
}
