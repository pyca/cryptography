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
typedef struct dsa_method {
    const char *name;
    DSA_SIG * (*dsa_do_sign)(const unsigned char *dgst, int dlen, DSA *dsa);
    int (*dsa_sign_setup)(DSA *dsa, BN_CTX *ctx_in, BIGNUM **kinvp,
                            BIGNUM **rp);
    ...;
} DSA_METHOD;
typedef struct ... DSA_SIG;
"""

FUNCTIONS = """
// DSA_generate_parameters() is deprecated in favor
// of DSA_generate_parameters_ex()
int DSA_generate_parameters_ex(DSA *, int, unsigned char *, int, int *,
                            unsigned long *, BN_GENCB *)
int DSA_generate_key(DSA *);
DSA *DSA_new(void);
void DSA_free(DSA *);
int DSA_sign_setup(DSA *, BN_CTX *, BIGNUM **, BIGNUM **)
int DSA_sign(int, const unsigned char *, int, unsigned char *, unsigned int *,
                            DSA *)
int DSA_verify(int, const unsigned char *, int, const unsigned char *, int,
                            DSA *)
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
