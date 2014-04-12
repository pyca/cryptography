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
#include <openssl/cmac.h>
"""

TYPES = """
typedef struct CMAC_CTX_st CMAC_CTX;
"""

FUNCTIONS = """
int CMAC_Init(CMAC_CTX *, const void *, size_t, const EVP_CIPHER *, ENGINE *);
int CMAC_Update(CMAC_CTX *, const void *, size_t);
int CMAC_Final(CMAC_CTX *, unsigned char *, size_t *);
int CMAC_CTX_copy(CMAC_CTX *, const CMAC_CTX *);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
