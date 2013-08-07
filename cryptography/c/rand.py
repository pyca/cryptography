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
