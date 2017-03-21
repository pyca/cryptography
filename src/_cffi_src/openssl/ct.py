# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/ct.h>
"""

TYPES = """
typedef enum {
    SCT_VERSION_NOT_SET,
    SCT_VERSION_V1
} sct_version_t;

typedef enum {
    CT_LOG_ENTRY_TYPE_NOT_SET,
    CT_LOG_ENTRY_TYPE_X509,
    CT_LOG_ENTRY_TYPE_PRECERT
} ct_log_entry_type_t;

typedef ... SCT;
"""

FUNCTIONS = """
sct_version_t SCT_get_version(const SCT *);

ct_log_entry_type_t SCT_get_log_entry_type(const SCT *);

size_t SCT_get0_log_id(const SCT *, unsigned char **);

uint64_t SCT_get_timestamp(const SCT *);
"""

MACROS = """
"""

CUSTOMIZATIONS = """
"""
