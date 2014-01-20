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
#include <openssl/dsa.h>
"""

TYPES = """
typedef struct dsa_st {
    // prime number (public)
    BIGNUM *p;
    // 160-bit subprime, q | p-1 (public)
    BIGNUM *q;
    // generator of subgroup (public)
    BIGNUM *g;
    // private key x
    BIGNUM *priv_key;
    // public key y = g^x
    BIGNUM *pub_key;
    ...;
} DSA;
"""

FUNCTIONS = """
DSA *DSA_generate_parameters(int, unsigned char *, int, int *, unsigned long *,
                             void (*)(int, int, void *), void *);
int DSA_generate_key(DSA *);
void DSA_free(DSA *);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
