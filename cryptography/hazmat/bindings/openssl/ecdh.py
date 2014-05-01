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
#ifdef OPENSSL_NO_ECDH
#include <openssl/ecdh.h>
#endif
"""

TYPES = """
static const int Cryptography_HAS_ECDH;

typedef ... ECDH_METHOD;
"""

FUNCTIONS = """
int ECDH_compute_key(void *, size_t, const EC_POINT *, EC_KEY *,
    void *(*)(const void *, size_t, void *, size_t *));

int ECDH_get_ex_new_index(long, void *, CRYPTO_EX_new *, CRYPTO_EX_dup *,
    CRYPTO_EX_free *);

int ECDH_set_ex_data(EC_KEY *, int, void *);

void *ECDH_get_ex_data(EC_KEY *, int);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {
}
