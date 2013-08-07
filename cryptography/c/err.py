INCLUDES = [
    '#include <openssl/err.h>',
    '#include <openssl/ssl.h>',
]

SETUP = [
    'SSL_load_error_strings',
]

TEARDOWN = [
    'ERR_free_strings',
]

TYPES = [
'struct ERR_string_data_st { unsigned long error; const char *string; };',
'typedef struct ERR_string_data_st ERR_STRING_DATA;',
]

FUNCTIONS = [
    'void ERR_load_crypto_strings(void);',
    'void ERR_free_strings(void);',
    'void SSL_load_error_strings(void);',
    'char* ERR_error_string(unsigned long e, char *buf);',
    'void ERR_error_string_n(unsigned long e, char *buf, size_t len);',
    'const char* ERR_lib_error_string(unsigned long e);',
    'const char* ERR_func_error_string(unsigned long e);',
    'const char* ERR_reason_error_string(unsigned long e);',
    'void ERR_print_errors(BIO *bp);',
    'void ERR_print_errors_fp(FILE *fp);',
    'unsigned long ERR_get_error(void);',
    'unsigned long ERR_peek_error(void);',
    'unsigned long ERR_peek_last_error(void);',
    'unsigned long ERR_get_error_line(const char **file, int *line);',
    'unsigned long ERR_peek_error_line(const char **file, int *line);',
    'unsigned long ERR_peek_last_error_line(const char **file, int *line);',
    'unsigned long ERR_get_error_line_data(const char **file, int *line, const char **data, int *flags);',
    'unsigned long ERR_peek_error_line_data(const char **file, int *line, const char **data, int *flags);',
    'unsigned long ERR_peek_last_error_line_data(const char **file, int *line, const char **data, int *flags);',
    'void ERR_put_error(int lib, int func, int reason, const char *file, int line);',
    'void ERR_add_error_data(int num, ...);',
    'void ERR_load_strings(int lib, ERR_STRING_DATA str[]);',
    'int ERR_get_next_error_library(void);',
    'unsigned long ERR_PACK(int lib, int func, int reason);',
    'int ERR_GET_LIB(unsigned long e);',
    'int ERR_GET_FUNC(unsigned long e);',
    'int ERR_GET_REASON(unsigned long e);',
]
