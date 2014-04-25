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
typedef struct {
    BIGNUM *r;
    BIGNUM *s;
} DSA_SIG;
"""

FUNCTIONS = """
DSA *DSA_generate_parameters(int, unsigned char *, int, int *, unsigned long *,
                             void (*)(int, int, void *), void *);
int DSA_generate_key(DSA *);
DSA *DSA_new(void);
void DSA_free(DSA *);
DSA_SIG *DSA_SIG_new(void);
void DSA_SIG_free(DSA_SIG *);
int i2d_DSA_SIG(const DSA_SIG *, unsigned char **);
DSA_SIG *d2i_DSA_SIG(DSA_SIG **, const unsigned char **, long);
int DSA_size(const DSA *);
int DSA_sign(int, const unsigned char *, int, unsigned char *, unsigned int *,
             DSA *);
int DSA_verify(int, const unsigned char *, int, const unsigned char *, int,
               DSA *);
"""

MACROS = """
int DSA_generate_parameters_ex(DSA *, int, unsigned char *, int,
                               int *, unsigned long *, BN_GENCB *);
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
