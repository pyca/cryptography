# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import annotations

INCLUDES = """
#include <openssl/evp.h>
"""

TYPES = """
typedef ... EVP_CIPHER;
typedef ... EVP_CIPHER_CTX;
typedef ... EVP_MD;
typedef ... EVP_MD_CTX;

typedef ... EVP_PKEY;
typedef ... EVP_PKEY_CTX;
static const int EVP_PKEY_RSA;
static const int EVP_PKEY_RSA_PSS;
static const int EVP_PKEY_DSA;
static const int EVP_PKEY_DH;
static const int EVP_PKEY_DHX;
static const int EVP_PKEY_EC;
static const int EVP_PKEY_X25519;
static const int EVP_PKEY_ED25519;
static const int EVP_PKEY_X448;
static const int EVP_PKEY_ED448;
static const int EVP_PKEY_POLY1305;
static const int EVP_MAX_MD_SIZE;
static const int EVP_CTRL_AEAD_SET_IVLEN;
static const int EVP_CTRL_AEAD_GET_TAG;
static const int EVP_CTRL_AEAD_SET_TAG;

static const int Cryptography_HAS_SCRYPT;
static const int Cryptography_HAS_EVP_PKEY_DHX;
static const long Cryptography_HAS_RAW_KEY;
static const long Cryptography_HAS_EVP_DIGESTFINAL_XOF;
static const long Cryptography_HAS_300_FIPS;
static const long Cryptography_HAS_300_EVP_CIPHER;
static const long Cryptography_HAS_EVP_PKEY_DH;
static const long Cryptography_HAS_EVP_PKEY_SET_PEER_EX;
"""

FUNCTIONS = """
const EVP_CIPHER *EVP_get_cipherbyname(const char *);
EVP_CIPHER *EVP_CIPHER_fetch(OSSL_LIB_CTX *, const char *, const char *);
void EVP_CIPHER_free(EVP_CIPHER *);

int EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *, int);
int EVP_CipherInit_ex(EVP_CIPHER_CTX *, const EVP_CIPHER *, ENGINE *,
                      const unsigned char *, const unsigned char *, int);
int EVP_CipherUpdate(EVP_CIPHER_CTX *, unsigned char *, int *,
                     const unsigned char *, int);
int EVP_CipherFinal_ex(EVP_CIPHER_CTX *, unsigned char *, int *);
int EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *);
EVP_CIPHER_CTX *EVP_CIPHER_CTX_new(void);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *);
int EVP_CIPHER_CTX_set_key_length(EVP_CIPHER_CTX *, int);

int EVP_DigestFinalXOF(EVP_MD_CTX *, unsigned char *, size_t);
const EVP_MD *EVP_get_digestbyname(const char *);

EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *);
int EVP_PKEY_type(int);
int EVP_PKEY_size(EVP_PKEY *);
RSA *EVP_PKEY_get1_RSA(EVP_PKEY *);

int EVP_PKEY_encrypt(EVP_PKEY_CTX *, unsigned char *, size_t *,
                     const unsigned char *, size_t);
int EVP_PKEY_decrypt(EVP_PKEY_CTX *, unsigned char *, size_t *,
                     const unsigned char *, size_t);

int EVP_SignInit(EVP_MD_CTX *, const EVP_MD *);
int EVP_SignUpdate(EVP_MD_CTX *, const void *, size_t);
int EVP_SignFinal(EVP_MD_CTX *, unsigned char *, unsigned int *, EVP_PKEY *);

int EVP_VerifyInit(EVP_MD_CTX *, const EVP_MD *);
int EVP_VerifyUpdate(EVP_MD_CTX *, const void *, size_t);
int EVP_VerifyFinal(EVP_MD_CTX *, const unsigned char *, unsigned int,
                    EVP_PKEY *);


EVP_PKEY_CTX *EVP_PKEY_CTX_new(EVP_PKEY *, ENGINE *);
void EVP_PKEY_CTX_free(EVP_PKEY_CTX *);
int EVP_PKEY_sign_init(EVP_PKEY_CTX *);
int EVP_PKEY_sign(EVP_PKEY_CTX *, unsigned char *, size_t *,
                  const unsigned char *, size_t);
int EVP_PKEY_verify_init(EVP_PKEY_CTX *);
int EVP_PKEY_verify(EVP_PKEY_CTX *, const unsigned char *, size_t,
                    const unsigned char *, size_t);
int EVP_PKEY_verify_recover_init(EVP_PKEY_CTX *);
int EVP_PKEY_verify_recover(EVP_PKEY_CTX *, unsigned char *,
                            size_t *, const unsigned char *, size_t);
int EVP_PKEY_encrypt_init(EVP_PKEY_CTX *);
int EVP_PKEY_decrypt_init(EVP_PKEY_CTX *);

int EVP_PKEY_set1_RSA(EVP_PKEY *, RSA *);
int EVP_PKEY_set1_DSA(EVP_PKEY *, DSA *);
int EVP_PKEY_set1_DH(EVP_PKEY *, DH *);

int EVP_PKEY_cmp(const EVP_PKEY *, const EVP_PKEY *);

int EVP_PKEY_derive_init(EVP_PKEY_CTX *);
int EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *, EVP_PKEY *);
int EVP_PKEY_derive_set_peer_ex(EVP_PKEY_CTX *, EVP_PKEY *, int);
int EVP_PKEY_derive(EVP_PKEY_CTX *, unsigned char *, size_t *);

int EVP_PKEY_id(const EVP_PKEY *);

EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *);

int EVP_PKEY_bits(const EVP_PKEY *);

int EVP_PKEY_assign_RSA(EVP_PKEY *, RSA *);

EC_KEY *EVP_PKEY_get1_EC_KEY(EVP_PKEY *);
int EVP_PKEY_set1_EC_KEY(EVP_PKEY *, EC_KEY *);

int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX *, int, int, void *);

int EVP_PKEY_CTX_set_signature_md(EVP_PKEY_CTX *, const EVP_MD *);

EVP_PKEY *EVP_PKEY_new_raw_private_key(int, ENGINE *, const unsigned char *,
                                       size_t);
EVP_PKEY *EVP_PKEY_new_raw_public_key(int, ENGINE *, const unsigned char *,
                                      size_t);
int EVP_PKEY_get_raw_private_key(const EVP_PKEY *, unsigned char *, size_t *);
int EVP_PKEY_get_raw_public_key(const EVP_PKEY *, unsigned char *, size_t *);

int EVP_default_properties_is_fips_enabled(OSSL_LIB_CTX *);
int EVP_default_properties_enable_fips(OSSL_LIB_CTX *, int);
"""

CUSTOMIZATIONS = """
#ifdef EVP_PKEY_DHX
const long Cryptography_HAS_EVP_PKEY_DHX = 1;
#else
const long Cryptography_HAS_EVP_PKEY_DHX = 0;
const long EVP_PKEY_DHX = -1;
#endif

#if CRYPTOGRAPHY_IS_LIBRESSL || defined(OPENSSL_NO_SCRYPT)
static const long Cryptography_HAS_SCRYPT = 0;
#else
static const long Cryptography_HAS_SCRYPT = 1;
#endif

#if CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_EVP_DIGESTFINAL_XOF = 0;
int (*EVP_DigestFinalXOF)(EVP_MD_CTX *, unsigned char *, size_t) = NULL;
#if CRYPTOGRAPHY_LIBRESSL_LESS_THAN_370
static const long Cryptography_HAS_RAW_KEY = 0;
EVP_PKEY *(*EVP_PKEY_new_raw_private_key)(int, ENGINE *, const unsigned char *,
                                       size_t) = NULL;
EVP_PKEY *(*EVP_PKEY_new_raw_public_key)(int, ENGINE *, const unsigned char *,
                                      size_t) = NULL;
int (*EVP_PKEY_get_raw_private_key)(const EVP_PKEY *, unsigned char *,
                                    size_t *) = NULL;
int (*EVP_PKEY_get_raw_public_key)(const EVP_PKEY *, unsigned char *,
                                   size_t *) = NULL;
#else
static const long Cryptography_HAS_RAW_KEY = 1;
#endif
#else
static const long Cryptography_HAS_RAW_KEY = 1;
static const long Cryptography_HAS_EVP_DIGESTFINAL_XOF = 1;
#endif

#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER
static const long Cryptography_HAS_EVP_PKEY_SET_PEER_EX = 1;
#else
static const long Cryptography_HAS_EVP_PKEY_SET_PEER_EX = 0;
int (*EVP_PKEY_derive_set_peer_ex)(EVP_PKEY_CTX *, EVP_PKEY *, int) = NULL;
#endif

/* This is tied to X25519 support so we reuse the Cryptography_HAS_X25519
   conditional to remove it. OpenSSL 1.1.0 didn't have this define, but
   1.1.1 will when it is released. We can remove this in the distant
   future when we drop 1.1.0 support. */
#ifndef EVP_PKEY_X25519
#define EVP_PKEY_X25519 NID_X25519
#endif

/* This is tied to X448 support so we reuse the Cryptography_HAS_X448
   conditional to remove it. OpenSSL 1.1.1 adds this define.  We can remove
   this in the distant future when we drop 1.1.0 support. */
#ifndef EVP_PKEY_X448
#define EVP_PKEY_X448 NID_X448
#endif

/* This is tied to ED25519 support so we reuse the Cryptography_HAS_ED25519
   conditional to remove it. */
#ifndef EVP_PKEY_ED25519
#define EVP_PKEY_ED25519 NID_ED25519
#endif

/* This is tied to ED448 support so we reuse the Cryptography_HAS_ED448
   conditional to remove it. */
#ifndef EVP_PKEY_ED448
#define EVP_PKEY_ED448 NID_ED448
#endif

/* This is tied to poly1305 support so we reuse the Cryptography_HAS_POLY1305
   conditional to remove it. */
#ifndef EVP_PKEY_POLY1305
#define EVP_PKEY_POLY1305 NID_poly1305
#endif

#if CRYPTOGRAPHY_OPENSSL_300_OR_GREATER
static const long Cryptography_HAS_300_FIPS = 1;
static const long Cryptography_HAS_300_EVP_CIPHER = 1;
#else
static const long Cryptography_HAS_300_FIPS = 0;
static const long Cryptography_HAS_300_EVP_CIPHER = 0;
int (*EVP_default_properties_is_fips_enabled)(OSSL_LIB_CTX *) = NULL;
int (*EVP_default_properties_enable_fips)(OSSL_LIB_CTX *, int) = NULL;
EVP_CIPHER * (*EVP_CIPHER_fetch)(OSSL_LIB_CTX *, const char *,
                                 const char *) = NULL;
void (*EVP_CIPHER_free)(EVP_CIPHER *) = NULL;
#endif

#if CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_EVP_PKEY_DH = 0;
int (*EVP_PKEY_set1_DH)(EVP_PKEY *, DH *) = NULL;
#else
static const long Cryptography_HAS_EVP_PKEY_DH = 1;
#endif
"""
