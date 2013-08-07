INCLUDES = [
    '#include "openssl/ssl.h"',
]

TYPES = [
    'static const int SSLEAY_VERSION;',
    'static const int SSLEAY_CFLAGS;',
    'static const int SSLEAY_BUILT_ON;',
    'static const int SSLEAY_PLATFORM;',
    'static const int SSLEAY_DIR;',
]

FUNCTIONS = [
    "long SSLeay(void);",
    "const char* SSLeay_version(int);",
]
