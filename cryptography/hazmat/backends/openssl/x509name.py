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
#include <openssl/x509.h>
"""

TYPES = """
typedef ... X509_NAME;
typedef ... X509_NAME_ENTRY;
"""

FUNCTIONS = """
int X509_NAME_entry_count(X509_NAME *);
X509_NAME_ENTRY *X509_NAME_get_entry(X509_NAME *, int);
ASN1_OBJECT *X509_NAME_ENTRY_get_object(X509_NAME_ENTRY *);
ASN1_STRING *X509_NAME_ENTRY_get_data(X509_NAME_ENTRY *);
unsigned long X509_NAME_hash(X509_NAME *);

int i2d_X509_NAME(X509_NAME *, unsigned char **);
int X509_NAME_add_entry_by_NID(X509_NAME *, int, int, unsigned char *,
                               int, int, int);
X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *, int);
void X509_NAME_ENTRY_free(X509_NAME_ENTRY *);
int X509_NAME_get_index_by_NID(X509_NAME *, int, int);
int X509_NAME_cmp(const X509_NAME *, const X509_NAME *);
char *X509_NAME_oneline(X509_NAME *, char *, int);
X509_NAME *X509_NAME_dup(X509_NAME *);
void X509_NAME_free(X509_NAME *);
"""

MACROS = """
struct stack_st_X509_NAME *sk_X509_NAME_new_null();
int sk_X509_NAME_num(struct stack_st_X509_NAME *);
int sk_X509_NAME_push(struct stack_st_X509_NAME *, X509_NAME *);
X509_NAME *sk_X509_NAME_value(struct stack_st_X509_NAME *, int);
void sk_X509_NAME_free(struct stack_st_X509_NAME *);
"""

CUSTOMIZATIONS = """
"""
