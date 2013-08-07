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

INCLUDES = [
    '#include <openssl/rand.h>',
]

FUNCTIONS = [
    'void RAND_seed(const void *buf, int num);',
    'void RAND_add(const void *buf, int num, double entropy);',
    'int RAND_status(void);',
    'int RAND_egd(const char *path);',
    'int RAND_egd_bytes(const char *path, int bytes);',
    'int RAND_query_egd_bytes(const char *path, unsigned char *buf, int bytes);',
    'const char *RAND_file_name(char *buf, size_t num);',
    'int RAND_load_file(const char *filename, long max_bytes);',
    'int RAND_write_file(const char *filename);',
    'void RAND_cleanup(void);',
    'int RAND_bytes(unsigned char *buf, int num);',
    'int RAND_pseudo_bytes(unsigned char *buf, int num);',
]
