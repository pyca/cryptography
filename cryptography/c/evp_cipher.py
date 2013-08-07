INCLUDES = [
    '#include "openssl/evp.h"',
]

TYPES = [
    'static const int EVP_CIPH_ECB_MODE;',
    'static const int EVP_CIPH_CBC_MODE;',
    'static const int EVP_CIPH_CFB_MODE;',
    'static const int EVP_CIPH_OFB_MODE;',
    'static const int EVP_CIPH_STREAM_CIPHER;',
    'struct evp_cipher_ctx_st { ...; };',
    'typedef ... EVP_CIPHER;',
    'typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;',
]

FUNCTIONS = [
    'void EVP_CIPHER_CTX_init(EVP_CIPHER_CTX *a);',
    # encrypt_ex
    'int EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char *iv);',
    'int EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl);',
    'int EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);',
    # decrypt_ex
    'int EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char *iv);',
    'int EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl);',
    'int EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);',
    # cipher_ex
    'int EVP_CipherInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, ENGINE *impl, unsigned char *key, unsigned char *iv, int enc);',
    'int EVP_CipherUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, unsigned char *in, int inl);',
    'int EVP_CipherFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);',
    # encrypt
    'int EVP_EncryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, unsigned char *key, unsigned char *iv);',
    'int EVP_EncryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);',
    # decrypt
    'int EVP_DecryptInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, unsigned char *key, unsigned char *iv);',
    'int EVP_DecryptFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);',
    # cipher
    'int EVP_CipherInit(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *type, unsigned char *key, unsigned char *iv, int enc);',
    'int EVP_CipherFinal(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl);',
    # control
    'int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *x, int padding);',
    'int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *x, int keylen);',
    'int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr);',
    'int EVP_CIPHER_CTX_cleanup(EVP_CIPHER_CTX *a);',
    'const EVP_CIPHER *EVP_get_cipherbyname(const char *name);',
    # cipher macros
    'const EVP_CIPHER *EVP_get_cipherbynid(int n);',
    'const EVP_CIPHER *EVP_get_cipherbyobj(const ASN1_OBJECT *o);',
    'int EVP_CIPHER_nid(const EVP_CIPHER *cipher);',
    'int EVP_CIPHER_block_size(const EVP_CIPHER *cipher);',
    'int EVP_CIPHER_key_length(const EVP_CIPHER *cipher);',
    'int EVP_CIPHER_iv_length(const EVP_CIPHER *cipher);',
    'unsigned long EVP_CIPHER_flags(const EVP_CIPHER *cipher);',
    'unsigned long EVP_CIPHER_mode(const EVP_CIPHER *cipher);',
    'int EVP_CIPHER_type(const EVP_CIPHER *ctx);',
    # ctx macros
    'const EVP_CIPHER *EVP_CIPHER_CTX_cipher(const EVP_CIPHER_CTX *ctx);',
    'int EVP_CIPHER_CTX_nid(const EVP_CIPHER_CTX *ctx);',
    'int EVP_CIPHER_CTX_block_size(const EVP_CIPHER_CTX *ctx);',
    'int EVP_CIPHER_CTX_key_length(const EVP_CIPHER_CTX *ctx);',
    'int EVP_CIPHER_CTX_iv_length(const EVP_CIPHER_CTX *ctx);',
    'void *EVP_CIPHER_CTX_get_app_data(const EVP_CIPHER_CTX *ctx);',
    'void EVP_CIPHER_CTX_set_app_data(EVP_CIPHER_CTX *ctx, void *data);',
    'int EVP_CIPHER_CTX_type(const EVP_CIPHER_CTX *ctx);',
    'unsigned long EVP_CIPHER_CTX_flags(const EVP_CIPHER_CTX *ctx);',
    'unsigned long EVP_CIPHER_CTX_mode(const EVP_CIPHER_CTX *ctx);',
    'int EVP_CIPHER_param_to_asn1(EVP_CIPHER_CTX *c, ASN1_TYPE *type);',
    'int EVP_CIPHER_asn1_to_param(EVP_CIPHER_CTX *c, ASN1_TYPE *type);',
]
