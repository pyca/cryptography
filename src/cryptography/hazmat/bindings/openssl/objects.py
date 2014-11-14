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
#include <openssl/objects.h>
"""

TYPES = """
"""

FUNCTIONS = """
ASN1_OBJECT *OBJ_nid2obj(int);
const char *OBJ_nid2ln(int);
const char *OBJ_nid2sn(int);
int OBJ_obj2nid(const ASN1_OBJECT *);
int OBJ_ln2nid(const char *);
int OBJ_sn2nid(const char *);
int OBJ_txt2nid(const char *);
ASN1_OBJECT *OBJ_txt2obj(const char *, int);
int OBJ_obj2txt(char *, int, const ASN1_OBJECT *, int);
int OBJ_cmp(const ASN1_OBJECT *, const ASN1_OBJECT *);
ASN1_OBJECT *OBJ_dup(const ASN1_OBJECT *);
int OBJ_create(const char *, const char *, const char *);
void OBJ_cleanup(void);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""

CONDITIONAL_NAMES = {}
