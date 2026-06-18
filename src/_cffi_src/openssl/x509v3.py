# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/x509v3.h>
"""

TYPES = """
typedef ... GENERAL_NAMES;

/* Only include the one union element used by pyOpenSSL. */
typedef struct {
    int type;
    union {
        ASN1_IA5STRING *ia5;   /* rfc822Name, dNSName, */
                               /*   uniformResourceIdentifier */
    } d;
    ...;
} GENERAL_NAME;
"""

FUNCTIONS = """
"""

CUSTOMIZATIONS = """
"""
