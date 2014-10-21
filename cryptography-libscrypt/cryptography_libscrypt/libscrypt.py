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
#include <libscrypt.h>
"""

TYPES = """
static const int SCRYPT_HASH_LEN;
static const int SCRYPT_MCF_LEN;
static const char *const SCRYPT_MCF_ID;
static const int SCRYPT_N;
static const int SCRYPT_r;
static const int SCRYPT_p;
"""

FUNCTIONS = """
int libscrypt_scrypt(const uint8_t *, size_t, const uint8_t *, size_t,
                     uint64_t, uint32_t, uint32_t, uint8_t *, size_t);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
