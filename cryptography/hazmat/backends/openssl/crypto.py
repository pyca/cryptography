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
#include <openssl/crypto.h>
"""

TYPES = """
static const int SSLEAY_VERSION;
static const int SSLEAY_CFLAGS;
static const int SSLEAY_PLATFORM;
static const int SSLEAY_DIR;
static const int SSLEAY_BUILT_ON;
"""

FUNCTIONS = """
unsigned long SSLeay(void);
const char *SSLeay_version(int);

void CRYPTO_free(void *);
int CRYPTO_mem_ctrl(int);
int CRYPTO_is_mem_check_on(void);
void CRYPTO_mem_leaks(struct bio_st *);
void CRYPTO_cleanup_all_ex_data(void);

void OPENSSL_free(void *);
"""

MACROS = """
void CRYPTO_add(int *, int, int);
void CRYPTO_malloc_init(void);
void CRYPTO_malloc_debug_init(void);

#define CRYPTO_MEM_CHECK_ON ...
#define CRYPTO_MEM_CHECK_OFF ...
#define CRYPTO_MEM_CHECK_ENABLE ...
#define CRYPTO_MEM_CHECK_DISABLE ...
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
