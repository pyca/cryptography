# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

import cffi

INCLUDES = """
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
"""

TYPES = """
static const long Cryptography_STATIC_CALLBACKS;

/* crypto.h
 * CRYPTO_set_locking_callback
 * void (*cb)(int mode, int type, const char *file, int line)
 */
extern "Python" void Cryptography_locking_cb(int, int, const char *, int);

/* pem.h
 * int pem_password_cb(char *buf, int size, int rwflag, void *userdata);
 */
extern "Python" int Cryptography_pem_password_cb(char *, int, int, void *);

/* rand.h
 * int (*bytes)(unsigned char *buf, int num);
 * int (*status)(void);
 */
extern "Python" int Cryptography_rand_bytes(unsigned char *, int);
extern "Python" int Cryptography_rand_status(void);

/* ssl.h
 *
 * SSL_CTX_set_cert_verify_callback
 * int (*cert_verify_callback)(X509_STORE_CTX *ctx, void *userdata)
 */
extern "Python" int Cryptography_cert_verify_cb(
    X509_STORE_CTX *, void *);

/* SSL_CTX_set_info_callback
 * void (*info_callback)(const SSL *ssl, int type, int val)
 */
extern "Python" void Cryptography_ssl_info_cb(
    const SSL *, int, int);

/* SSL_CTX_set_msg_callback
 * void (*info_callback)(int write_p, int version, int content_type,
 *                       const void *buf, size_t len, SSL *ssl, void *arg)
 */
extern "Python" void Cryptography_msg_cb(
    int, int, int, const void *, size_t, SSL *, void *);

/* SSL_CTX_set_client_cert_cb
 * int (*client_cert_cb) (SSL *ssl, X509 **x509, EVP_PKEY **pkey)
 */
extern "Python" int Cryptography_client_cert_cb(
    SSL *, X509 **, EVP_PKEY **);

/* SSL_CTX_set_next_protos_advertised_cb
 * int (*cb)(SSL *ssl, const unsigned char **out, unsigned int *outlen,
 *           void *arg
 */
extern "Python" int Cryptography_next_proto_advertised_cb(
    SSL *, const unsigned char **, unsigned int *, void *);

/* SSL_CTX_set_next_proto_select_cb
 * int (*cb) (SSL *ssl, unsigned char **out, unsigned char *outlen,
 *            const unsigned char *in, unsigned int inlen, void *arg)
 */
extern "Python" int Cryptography_next_proto_select_cb(
    SSL *, unsigned char **, unsigned char *, const unsigned char *,
    unsigned int, void *);

/* SSL_CTX_set_alpn_select_cb
 * int (*cb) (SSL *ssl, const unsigned char **out, unsigned char *outlen,
              const unsigned char *in, unsigned int inlen, void *arg)
 */
extern "Python" int Cryptography_alpn_select_cb(
    SSL *, const unsigned char **, unsigned char *, const unsigned char *,
    unsigned int, void *arg);

/* tls1.h
 * SSL_CTX_set_tlsext_servername_callback
 */
extern "Python" int Cryptography_tlsext_servername_cb(
    const SSL *, int *, void *);

/* x509_vfy.h
 * int (*verify_cb)(int ok, X509_STORE_CTX *ctx)
 */
extern "Python" int Cryptography_verify_cb(int, X509_STORE_CTX *);
"""

FUNCTIONS = """
"""

MACROS = """
"""

CUSTOMIZATIONS = """
static const long Cryptography_STATIC_CALLBACKS = 1;
"""

if cffi.__version_info__ < (1, 4, 0):
    # backwards compatibility for old cffi version on PyPy
    TYPES = "static const long Cryptography_STATIC_CALLBACKS;"
    CUSTOMIZATIONS = "static const long Cryptography_STATIC_CALLBACKS = 0;"
