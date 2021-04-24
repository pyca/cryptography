# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/objects.h>
"""

TYPES = """
typedef struct {
    int type;
    int alias;
    const char *name;
    const char *data;
} OBJ_NAME;

static const long OBJ_NAME_TYPE_MD_METH;
"""

FUNCTIONS = """
const char *OBJ_nid2ln(int);
const char *OBJ_nid2sn(int);
int OBJ_obj2nid(const ASN1_OBJECT *);
int OBJ_sn2nid(const char *);
int OBJ_txt2nid(const char *);
ASN1_OBJECT *OBJ_txt2obj(const char *, int);
int OBJ_obj2txt(char *, int, const ASN1_OBJECT *, int);

const unsigned char *Cryptography_OBJ_get0_data(const ASN1_OBJECT *);
size_t Cryptography_OBJ_length(const ASN1_OBJECT *);
"""

CUSTOMIZATIONS = """
#if CRYPTOGRAPHY_IS_LIBRESSL
const unsigned char *Cryptography_OBJ_get0_data(const ASN1_OBJECT *a) {
    return a->data;
}

size_t Cryptography_OBJ_length(const ASN1_OBJECT *a) {
    return a->length;
}
#else
const unsigned char *Cryptography_OBJ_get0_data(const ASN1_OBJECT *a) {
    return OBJ_get0_data(a);
}

size_t Cryptography_OBJ_length(const ASN1_OBJECT *a) {
    return OBJ_length(a);
}
#endif
"""
