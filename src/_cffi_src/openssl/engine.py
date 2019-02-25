# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/engine.h>
"""

TYPES = """
typedef ... ENGINE;
typedef struct {
    int (*bytes)(unsigned char *, int);
    int (*pseudorand)(unsigned char *, int);
    int (*status)();
    ...;
} RAND_METHOD;
typedef int (*ENGINE_GEN_INT_FUNC_PTR)(ENGINE *);
typedef ... *ENGINE_CTRL_FUNC_PTR;
typedef ... *ENGINE_LOAD_KEY_PTR;
typedef ... *ENGINE_CIPHERS_PTR;
typedef ... *ENGINE_DIGESTS_PTR;
typedef ... ENGINE_CMD_DEFN;
typedef ... UI_METHOD;

static const unsigned int ENGINE_METHOD_RAND;

static const int ENGINE_R_CONFLICTING_ENGINE_ID;
"""

FUNCTIONS = """
ENGINE *ENGINE_get_first(void);
ENGINE *ENGINE_get_last(void);
int ENGINE_add(ENGINE *);
int ENGINE_remove(ENGINE *);
ENGINE *ENGINE_by_id(const char *);
int ENGINE_init(ENGINE *);
int ENGINE_finish(ENGINE *);
void ENGINE_load_builtin_engines(void);
ENGINE *ENGINE_get_default_RAND(void);
int ENGINE_set_default_RAND(ENGINE *);
int ENGINE_register_RAND(ENGINE *);
void ENGINE_unregister_RAND(ENGINE *);
void ENGINE_register_all_RAND(void);
int ENGINE_ctrl(ENGINE *, int, long, void *, void (*)(void));
int ENGINE_ctrl_cmd(ENGINE *, const char *, long, void *, void (*)(void), int);
int ENGINE_ctrl_cmd_string(ENGINE *, const char *, const char *, int);

ENGINE *ENGINE_new(void);
int ENGINE_free(ENGINE *);
int ENGINE_up_ref(ENGINE *);
int ENGINE_set_id(ENGINE *, const char *);
int ENGINE_set_name(ENGINE *, const char *);
int ENGINE_set_RAND(ENGINE *, const RAND_METHOD *);
int ENGINE_set_destroy_function(ENGINE *, ENGINE_GEN_INT_FUNC_PTR);
int ENGINE_set_init_function(ENGINE *, ENGINE_GEN_INT_FUNC_PTR);
int ENGINE_set_finish_function(ENGINE *, ENGINE_GEN_INT_FUNC_PTR);
int ENGINE_set_ctrl_function(ENGINE *, ENGINE_CTRL_FUNC_PTR);
const char *ENGINE_get_id(const ENGINE *);
const char *ENGINE_get_name(const ENGINE *);
const RAND_METHOD *ENGINE_get_RAND(const ENGINE *);

void ENGINE_add_conf_module(void);
/* these became macros in 1.1.0 */
void ENGINE_load_openssl(void);
void ENGINE_load_dynamic(void);
void ENGINE_cleanup(void);
"""

CUSTOMIZATIONS = """
"""
