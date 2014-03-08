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
#include <openssl/pkcs12.h>
"""

TYPES = """
typedef ... PKCS12;
"""

FUNCTIONS = """
void PKCS12_free(PKCS12 *);

PKCS12 *d2i_PKCS12_bio(BIO *, PKCS12 **);
int i2d_PKCS12_bio(BIO *, PKCS12 *);
"""

MACROS = """
int PKCS12_parse(PKCS12 *, const char *, EVP_PKEY **, X509 **,
                 Cryptography_STACK_OF_X509 **);
PKCS12 *PKCS12_create(char *, char *, EVP_PKEY *, X509 *,
                      Cryptography_STACK_OF_X509 *, int, int, int, int, int);
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
