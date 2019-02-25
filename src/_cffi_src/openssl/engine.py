# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/engine.h>
"""

TYPES = """
typedef ... ENGINE;

static const int ENGINE_R_CONFLICTING_ENGINE_ID;
static const long Cryptography_HAS_ENGINE;
"""

FUNCTIONS = """
int ENGINE_add(ENGINE *);
ENGINE *ENGINE_by_id(const char *);
int ENGINE_init(ENGINE *);
int ENGINE_finish(ENGINE *);
ENGINE *ENGINE_get_default_RAND(void);
int ENGINE_set_default_RAND(ENGINE *);
void ENGINE_unregister_RAND(ENGINE *);
int ENGINE_ctrl_cmd(ENGINE *, const char *, long, void *, void (*)(void), int);
int ENGINE_free(ENGINE *);
const char *ENGINE_get_name(const ENGINE *);

/* these became macros in 1.1.0 */
void ENGINE_load_dynamic(void);
"""

CUSTOMIZATIONS = """
#ifdef OPENSSL_NO_ENGINE
static const long Cryptography_HAS_ENGINE = 0;

static const int ENGINE_R_CONFLICTING_ENGINE_ID = 0;

int (*ENGINE_add)(ENGINE *) = NULL;
ENGINE *(*ENGINE_by_id)(const char *) = NULL;
int (*ENGINE_init)(ENGINE *) = NULL;
int (*ENGINE_finish)(ENGINE *) = NULL;
ENGINE *(*ENGINE_get_default_RAND)(void) = NULL;
int (*ENGINE_set_default_RAND)(ENGINE *) = NULL;
void (*ENGINE_unregister_RAND)(ENGINE *) = NULL;
int (*ENGINE_ctrl)(ENGINE *, int, long, void *, void (*)(void)) = NULL;
int (*ENGINE_ctrl_cmd)(ENGINE *, const char *, long, void *,
                       void (*)(void), int) = NULL;
int (*ENGINE_ctrl_cmd_string)(ENGINE *, const char *, const char *,
                              int) = NULL;

int (*ENGINE_free)(ENGINE *) = NULL;
const char *(*ENGINE_get_id)(const ENGINE *) = NULL;
const char *(*ENGINE_get_name)(const ENGINE *) = NULL;

/* these became macros in 1.1.0 */
void (*ENGINE_load_dynamic)(void) = NULL;
#else
static const long Cryptography_HAS_ENGINE = 1;
#endif
"""
