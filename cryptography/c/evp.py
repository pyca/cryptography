INCLUDES = [
    '#include "openssl/evp.h"',
]

TEARDOWN = [
    'EVP_cleanup',
]

TYPES = [
    'typedef ... ENGINE;',
]
