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
#include <openssl/bn.h>
"""

TYPES = """
typedef ... BIGNUM;

// Possibly belongs in an asn1.py
typedef ... ASN1_INTEGER;
"""

FUNCTIONS = """
BIGNUM *BN_new();
void BN_free(BIGNUM *);

int BN_set_word(BIGNUM *, unsigned long);

char *BN_bn2hex(const BIGNUM *);
int BN_hex2bn(BIGNUM **, const char *);

ASN1_INTEGER *BN_to_ASN1_INTEGER(const BIGNUM *, ASN1_INTEGER *);
"""
