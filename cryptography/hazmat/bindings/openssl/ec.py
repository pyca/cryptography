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
#ifndef OPENSSL_NO_EC
#include <openssl/ec.h>
#endif

#include <openssl/obj_mac.h>
"""

TYPES = """
static const int Cryptography_HAS_EC;

typedef ... EC_KEY;
typedef ... EC_builtin_curve;

static const int NID_X9_62_prime192v1;
static const int NID_X9_62_prime192v2;
static const int NID_X9_62_prime192v3;
static const int NID_X9_62_prime239v1;
static const int NID_X9_62_prime239v2;
static const int NID_X9_62_prime239v3;
static const int NID_X9_62_prime256v1;
"""

FUNCTIONS = """
"""

MACROS = """
EC_KEY *EC_KEY_new_by_curve_name(int);
void EC_KEY_free(EC_KEY *);

size_t EC_get_builtin_curves(EC_builtin_curve *, size_t);

int Cryptography_EC_builtin_curve_get_nid(EC_builtin_curve *);
"""

CUSTOMIZATIONS = """
#ifdef OPENSSL_NO_EC
static const long Cryptography_HAS_EC = 0;
typedef void EC_KEY;
typedef void EC_builtin_curve;
EC_KEY* (*EC_KEY_new_by_curve_name)(int) = NULL;
void (*EC_KEY_free)(EC_KEY *) = NULL;
size_t (*EC_get_builtin_curves)(EC_builtin_curve *, size_t) = NULL;
int (*Cryptography_EC_builtin_curve_get_nid)(EC_builtin_curve *) = NULL;
#else
static const long Cryptography_HAS_EC = 1;

int Cryptography_EC_builtin_curve_get_nid(EC_builtin_curve *c) {
    return c->nid;
}
#endif
"""

CONDITIONAL_NAMES = {
    "Cryptography_HAS_EC": [
        "EC_KEY_new_by_curve_name",
        "EC_KEY_free",
        "EC_get_builtin_curves",

        "Cryptography_EC_builtin_curve_get_nid",
    ],
}
