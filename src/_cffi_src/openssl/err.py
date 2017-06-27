# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/err.h>
"""

TYPES = """
static const int Cryptography_HAS_EC_CODES;
static const int Cryptography_HAS_RSA_R_PKCS_DECODING_ERROR;

struct ERR_string_data_st {
    unsigned long error;
    const char *string;
};
typedef struct ERR_string_data_st ERR_STRING_DATA;
typedef ... ERR_STATE;

static const int ERR_LIB_DH;
static const int ERR_LIB_EVP;
static const int ERR_LIB_EC;
static const int ERR_LIB_PEM;
static const int ERR_LIB_ASN1;
static const int ERR_LIB_RSA;
static const int ERR_LIB_PKCS12;
static const int ERR_LIB_SSL;
static const int ERR_LIB_X509;

static const int ASN1_F_ASN1_EX_C2I;
static const int ASN1_F_ASN1_FIND_END;
static const int ASN1_F_ASN1_GENERATE_V3;
static const int ASN1_F_ASN1_GET_OBJECT;
static const int ASN1_F_ASN1_ITEM_I2D_FP;
static const int ASN1_F_ASN1_ITEM_PACK;
static const int ASN1_F_ASN1_ITEM_SIGN;
static const int ASN1_F_ASN1_ITEM_UNPACK;
static const int ASN1_F_ASN1_ITEM_VERIFY;
static const int ASN1_F_ASN1_MBSTRING_NCOPY;
static const int ASN1_F_ASN1_TEMPLATE_EX_D2I;
static const int ASN1_F_ASN1_TEMPLATE_NEW;
static const int ASN1_F_ASN1_TEMPLATE_NOEXP_D2I;
static const int ASN1_F_ASN1_TYPE_GET_INT_OCTETSTRING;
static const int ASN1_F_ASN1_TYPE_GET_OCTETSTRING;
static const int ASN1_F_ASN1_VERIFY;
static const int ASN1_F_BITSTR_CB;
static const int ASN1_F_D2I_ASN1_UINTEGER;
static const int ASN1_F_D2I_PRIVATEKEY;
static const int ASN1_F_I2D_DSA_PUBKEY;
static const int ASN1_F_LONG_C2I;
static const int ASN1_F_OID_MODULE_INIT;
static const int ASN1_F_PARSE_TAGGING;
static const int ASN1_F_PKCS5_PBE_SET;
static const int ASN1_F_B64_READ_ASN1;
static const int ASN1_F_B64_WRITE_ASN1;
static const int ASN1_F_SMIME_READ_ASN1;
static const int ASN1_F_SMIME_TEXT;
static const int ASN1_F_ASN1_CHECK_TLEN;

static const int ASN1_R_BOOLEAN_IS_WRONG_LENGTH;
static const int ASN1_R_BUFFER_TOO_SMALL;
static const int ASN1_R_CIPHER_HAS_NO_OBJECT_IDENTIFIER;
static const int ASN1_R_DATA_IS_WRONG;
static const int ASN1_R_DECODE_ERROR;
static const int ASN1_R_DEPTH_EXCEEDED;
static const int ASN1_R_ENCODE_ERROR;
static const int ASN1_R_ERROR_GETTING_TIME;
static const int ASN1_R_ERROR_LOADING_SECTION;
static const int ASN1_R_MSTRING_WRONG_TAG;
static const int ASN1_R_NESTED_ASN1_STRING;
static const int ASN1_R_NO_MATCHING_CHOICE_TYPE;
static const int ASN1_R_UNKNOWN_MESSAGE_DIGEST_ALGORITHM;
static const int ASN1_R_UNKNOWN_OBJECT_TYPE;
static const int ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE;
static const int ASN1_R_UNKNOWN_TAG;
static const int ASN1_R_UNSUPPORTED_ANY_DEFINED_BY_TYPE;
static const int ASN1_R_UNSUPPORTED_PUBLIC_KEY_TYPE;
static const int ASN1_R_UNSUPPORTED_TYPE;
static const int ASN1_R_WRONG_TAG;
static const int ASN1_R_NO_CONTENT_TYPE;
static const int ASN1_R_NO_MULTIPART_BODY_FAILURE;
static const int ASN1_R_NO_MULTIPART_BOUNDARY;
static const int ASN1_R_HEADER_TOO_LONG;

static const int DH_F_COMPUTE_KEY;

static const int DH_R_INVALID_PUBKEY;

static const int EVP_F_AES_INIT_KEY;
static const int EVP_F_EVP_CIPHER_CTX_CTRL;
static const int EVP_F_EVP_CIPHER_CTX_SET_KEY_LENGTH;
static const int EVP_F_EVP_CIPHERINIT_EX;
static const int EVP_F_EVP_DECRYPTFINAL_EX;
static const int EVP_F_EVP_DIGESTINIT_EX;
static const int EVP_F_EVP_ENCRYPTFINAL_EX;
static const int EVP_F_EVP_MD_CTX_COPY_EX;
static const int EVP_F_EVP_OPENINIT;
static const int EVP_F_EVP_PBE_ALG_ADD;
static const int EVP_F_EVP_PBE_CIPHERINIT;
static const int EVP_F_EVP_PKCS82PKEY;
static const int EVP_F_EVP_PKEY_COPY_PARAMETERS;
static const int EVP_F_EVP_PKEY_DECRYPT;
static const int EVP_F_EVP_PKEY_ENCRYPT;
static const int EVP_F_EVP_PKEY_NEW;
static const int EVP_F_EVP_SIGNFINAL;
static const int EVP_F_EVP_VERIFYFINAL;
static const int EVP_F_PKCS5_PBE_KEYIVGEN;
static const int EVP_F_PKCS5_V2_PBE_KEYIVGEN;
static const int EVP_F_RC2_MAGIC_TO_METH;
static const int EVP_F_RC5_CTRL;
static const int EVP_F_CAMELLIA_INIT_KEY;

static const int EVP_R_AES_KEY_SETUP_FAILED;
static const int EVP_R_BAD_DECRYPT;
static const int EVP_R_CIPHER_PARAMETER_ERROR;
static const int EVP_R_CTRL_NOT_IMPLEMENTED;
static const int EVP_R_CTRL_OPERATION_NOT_IMPLEMENTED;
static const int EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH;
static const int EVP_R_DECODE_ERROR;
static const int EVP_R_DIFFERENT_KEY_TYPES;
static const int EVP_R_INITIALIZATION_ERROR;
static const int EVP_R_INPUT_NOT_INITIALIZED;
static const int EVP_R_INVALID_KEY_LENGTH;
static const int EVP_R_KEYGEN_FAILURE;
static const int EVP_R_MISSING_PARAMETERS;
static const int EVP_R_NO_CIPHER_SET;
static const int EVP_R_NO_DIGEST_SET;
static const int EVP_R_PUBLIC_KEY_NOT_RSA;
static const int EVP_R_UNKNOWN_PBE_ALGORITHM;
static const int EVP_R_UNSUPPORTED_CIPHER;
static const int EVP_R_UNSUPPORTED_KEY_DERIVATION_FUNCTION;
static const int EVP_R_UNSUPPORTED_KEYLENGTH;
static const int EVP_R_UNSUPPORTED_SALT_TYPE;
static const int EVP_R_UNSUPPORTED_PRIVATE_KEY_ALGORITHM;
static const int EVP_R_WRONG_FINAL_BLOCK_LENGTH;
static const int EVP_R_CAMELLIA_KEY_SETUP_FAILED;

static const int EC_F_EC_GROUP_NEW_BY_CURVE_NAME;

static const int EC_R_UNKNOWN_GROUP;

static const int PEM_F_D2I_PKCS8PRIVATEKEY_BIO;
static const int PEM_F_D2I_PKCS8PRIVATEKEY_FP;
static const int PEM_F_DO_PK8PKEY;
static const int PEM_F_DO_PK8PKEY_FP;
static const int PEM_F_LOAD_IV;
static const int PEM_F_PEM_ASN1_READ;
static const int PEM_F_PEM_ASN1_READ_BIO;
static const int PEM_F_PEM_ASN1_WRITE;
static const int PEM_F_PEM_ASN1_WRITE_BIO;
static const int PEM_F_PEM_DEF_CALLBACK;
static const int PEM_F_PEM_DO_HEADER;
static const int PEM_F_PEM_GET_EVP_CIPHER_INFO;
static const int PEM_F_PEM_READ;
static const int PEM_F_PEM_READ_BIO;
static const int PEM_F_PEM_READ_BIO_PRIVATEKEY;
static const int PEM_F_PEM_READ_PRIVATEKEY;
static const int PEM_F_PEM_SIGNFINAL;
static const int PEM_F_PEM_WRITE;
static const int PEM_F_PEM_WRITE_BIO;
static const int PEM_F_PEM_X509_INFO_READ;
static const int PEM_F_PEM_X509_INFO_READ_BIO;
static const int PEM_F_PEM_X509_INFO_WRITE_BIO;

static const int PEM_R_BAD_BASE64_DECODE;
static const int PEM_R_BAD_DECRYPT;
static const int PEM_R_BAD_END_LINE;
static const int PEM_R_BAD_IV_CHARS;
static const int PEM_R_BAD_PASSWORD_READ;
static const int PEM_R_ERROR_CONVERTING_PRIVATE_KEY;
static const int PEM_R_NO_START_LINE;
static const int PEM_R_NOT_DEK_INFO;
static const int PEM_R_NOT_ENCRYPTED;
static const int PEM_R_NOT_PROC_TYPE;
static const int PEM_R_PROBLEMS_GETTING_PASSWORD;
static const int PEM_R_READ_KEY;
static const int PEM_R_SHORT_HEADER;
static const int PEM_R_UNSUPPORTED_CIPHER;
static const int PEM_R_UNSUPPORTED_ENCRYPTION;

static const int PKCS12_F_PKCS12_PBE_CRYPT;

static const int PKCS12_R_PKCS12_CIPHERFINAL_ERROR;

static const int RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE;
static const int RSA_R_DATA_TOO_LARGE_FOR_MODULUS;
static const int RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY;
static const int RSA_R_BLOCK_TYPE_IS_NOT_01;
static const int RSA_R_BLOCK_TYPE_IS_NOT_02;
static const int RSA_R_PKCS_DECODING_ERROR;
static const int RSA_R_OAEP_DECODING_ERROR;
static const int RSA_F_RSA_SIGN;

static const int SSL_TLSEXT_ERR_OK;
static const int SSL_TLSEXT_ERR_ALERT_WARNING;
static const int SSL_TLSEXT_ERR_ALERT_FATAL;
static const int SSL_TLSEXT_ERR_NOACK;

static const int SSL_AD_CLOSE_NOTIFY;
static const int SSL_AD_UNEXPECTED_MESSAGE;
static const int SSL_AD_BAD_RECORD_MAC;
static const int SSL_AD_RECORD_OVERFLOW;
static const int SSL_AD_DECOMPRESSION_FAILURE;
static const int SSL_AD_HANDSHAKE_FAILURE;
static const int SSL_AD_BAD_CERTIFICATE;
static const int SSL_AD_UNSUPPORTED_CERTIFICATE;
static const int SSL_AD_CERTIFICATE_REVOKED;
static const int SSL_AD_CERTIFICATE_EXPIRED;
static const int SSL_AD_CERTIFICATE_UNKNOWN;
static const int SSL_AD_ILLEGAL_PARAMETER;
static const int SSL_AD_UNKNOWN_CA;
static const int SSL_AD_ACCESS_DENIED;
static const int SSL_AD_DECODE_ERROR;
static const int SSL_AD_DECRYPT_ERROR;
static const int SSL_AD_PROTOCOL_VERSION;
static const int SSL_AD_INSUFFICIENT_SECURITY;
static const int SSL_AD_INTERNAL_ERROR;
static const int SSL_AD_USER_CANCELLED;
static const int SSL_AD_NO_RENEGOTIATION;

static const int SSL_AD_UNSUPPORTED_EXTENSION;
static const int SSL_AD_CERTIFICATE_UNOBTAINABLE;
static const int SSL_AD_UNRECOGNIZED_NAME;
static const int SSL_AD_BAD_CERTIFICATE_STATUS_RESPONSE;
static const int SSL_AD_BAD_CERTIFICATE_HASH_VALUE;
static const int SSL_AD_UNKNOWN_PSK_IDENTITY;

static const int X509_R_CERT_ALREADY_IN_HASH_TABLE;
"""

FUNCTIONS = """
char *ERR_error_string(unsigned long, char *);
void ERR_error_string_n(unsigned long, char *, size_t);
const char *ERR_lib_error_string(unsigned long);
const char *ERR_func_error_string(unsigned long);
const char *ERR_reason_error_string(unsigned long);
void ERR_print_errors(BIO *);
void ERR_print_errors_fp(FILE *);
unsigned long ERR_get_error(void);
unsigned long ERR_peek_error(void);
unsigned long ERR_peek_last_error(void);
unsigned long ERR_get_error_line(const char **, int *);
unsigned long ERR_peek_error_line(const char **, int *);
unsigned long ERR_peek_last_error_line(const char **, int *);
unsigned long ERR_get_error_line_data(const char **, int *,
                                      const char **, int *);
void ERR_clear_error(void);
unsigned long ERR_peek_error_line_data(const char **,
                                       int *, const char **, int *);
unsigned long ERR_peek_last_error_line_data(const char **,
                                            int *, const char **, int *);
void ERR_put_error(int, int, int, const char *, int);
void ERR_add_error_data(int, ...);
int ERR_get_next_error_library(void);
ERR_STATE *ERR_get_state(void);
/* ERR_free_strings became a macro in 1.1.0 */
void ERR_free_strings(void);

unsigned long ERR_PACK(int, int, int);
int ERR_GET_LIB(unsigned long);
int ERR_GET_FUNC(unsigned long);
int ERR_GET_REASON(unsigned long);

"""

CUSTOMIZATIONS = """
static const long Cryptography_HAS_EC_CODES = 1;

#ifdef RSA_R_PKCS_DECODING_ERROR
static const long Cryptography_HAS_RSA_R_PKCS_DECODING_ERROR = 1;
#else
static const long Cryptography_HAS_RSA_R_PKCS_DECODING_ERROR = 0;
static const long RSA_R_PKCS_DECODING_ERROR = 0;
#endif
"""
