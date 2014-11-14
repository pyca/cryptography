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
#include <openssl/rand.h>
"""

TYPES = """
"""

FUNCTIONS = """
void ERR_load_RAND_strings(void);
void RAND_seed(const void *, int);
void RAND_add(const void *, int, double);
int RAND_status(void);
int RAND_egd(const char *);
int RAND_egd_bytes(const char *, int);
int RAND_query_egd_bytes(const char *, unsigned char *, int);
const char *RAND_file_name(char *, size_t);
int RAND_load_file(const char *, long);
int RAND_write_file(const char *);
void RAND_cleanup(void);
int RAND_bytes(unsigned char *, int);
int RAND_pseudo_bytes(unsigned char *, int);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
