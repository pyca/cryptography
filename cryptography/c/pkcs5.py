INCLUDES = [
    '#include "openssl/evp.h"',
]

FUNCTIONS = [
    'int PKCS5_PBKDF2_HMAC_SHA1(const char *pass, int passlen,'
        'const unsigned char *salt, int saltlen, int iter,'
        'int keylen, unsigned char *out);',
    'int EVP_BytesToKey(const EVP_CIPHER *type,const EVP_MD *md,'
        'const unsigned char *salt,'
        'const unsigned char *data, int datal, int count,'
        'unsigned char *key,unsigned char *iv);',
]
