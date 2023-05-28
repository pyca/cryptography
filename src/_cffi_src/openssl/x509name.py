# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/x509.h>

/*
 * See the comment above Cryptography_STACK_OF_X509 in x509.py
 */
typedef STACK_OF(X509_NAME) Cryptography_STACK_OF_X509_NAME;
typedef STACK_OF(X509_NAME_ENTRY) Cryptography_STACK_OF_X509_NAME_ENTRY;
"""

TYPES = """
typedef ... Cryptography_STACK_OF_X509_NAME_ENTRY;
typedef ... X509_NAME;
typedef ... X509_NAME_ENTRY;
typedef ... Cryptography_STACK_OF_X509_NAME;
"""

FUNCTIONS = """
X509_NAME *X509_NAME_new(void);
void X509_NAME_free(X509_NAME *);

unsigned long X509_NAME_hash(X509_NAME *);

int i2d_X509_NAME(X509_NAME *, unsigned char **);
X509_NAME_ENTRY *X509_NAME_delete_entry(X509_NAME *, int);
void X509_NAME_ENTRY_free(X509_NAME_ENTRY *);
int X509_NAME_get_index_by_NID(X509_NAME *, int, int);
int X509_NAME_cmp(const X509_NAME *, const X509_NAME *);
X509_NAME *X509_NAME_dup(X509_NAME *);
int X509_NAME_entry_count(const X509_NAME *);
X509_NAME_ENTRY *X509_NAME_get_entry(const X509_NAME *, int);
char *X509_NAME_oneline(const X509_NAME *, char *, int);

ASN1_OBJECT *X509_NAME_ENTRY_get_object(const X509_NAME_ENTRY *);
ASN1_STRING *X509_NAME_ENTRY_get_data(const X509_NAME_ENTRY *);

int X509_NAME_add_entry_by_NID(X509_NAME *, int, int, const unsigned char *,
                               int, int, int);

Cryptography_STACK_OF_X509_NAME *sk_X509_NAME_new_null(void);
int sk_X509_NAME_num(Cryptography_STACK_OF_X509_NAME *);
int sk_X509_NAME_push(Cryptography_STACK_OF_X509_NAME *, X509_NAME *);
X509_NAME *sk_X509_NAME_value(Cryptography_STACK_OF_X509_NAME *, int);
void sk_X509_NAME_free(Cryptography_STACK_OF_X509_NAME *);
"""

CUSTOMIZATIONS = """
"""
