# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

INCLUDES = """
#include <openssl/ssl.h>

typedef STACK_OF(SSL_CIPHER) Cryptography_STACK_OF_SSL_CIPHER;
"""

TYPES = """
static const long Cryptography_HAS_SSL_ST;
static const long Cryptography_HAS_TLS_ST;
static const long Cryptography_HAS_SSL2;
static const long Cryptography_HAS_SSL3_METHOD;
static const long Cryptography_HAS_TLSv1_1;
static const long Cryptography_HAS_TLSv1_2;
static const long Cryptography_HAS_SECURE_RENEGOTIATION;
static const long Cryptography_HAS_COMPRESSION;
static const long Cryptography_HAS_TLSEXT_STATUS_REQ_CB;
static const long Cryptography_HAS_STATUS_REQ_OCSP_RESP;
static const long Cryptography_HAS_TLSEXT_STATUS_REQ_TYPE;
static const long Cryptography_HAS_GET_SERVER_TMP_KEY;
static const long Cryptography_HAS_SSL_CTX_SET_CLIENT_CERT_ENGINE;
static const long Cryptography_HAS_SSL_CTX_CLEAR_OPTIONS;
static const long Cryptography_HAS_DTLS;
static const long Cryptography_HAS_GENERIC_DTLS_METHOD;

/* Internally invented symbol to tell us if SNI is supported */
static const long Cryptography_HAS_TLSEXT_HOSTNAME;

/* Internally invented symbol to tell us if SSL_MODE_RELEASE_BUFFERS is
 * supported
 */
static const long Cryptography_HAS_RELEASE_BUFFERS;

/* Internally invented symbol to tell us if SSL_OP_NO_COMPRESSION is
 * supported
 */
static const long Cryptography_HAS_OP_NO_COMPRESSION;
static const long Cryptography_HAS_SSL_OP_MSIE_SSLV2_RSA_PADDING;
static const long Cryptography_HAS_SSL_SET_SSL_CTX;
static const long Cryptography_HAS_SSL_OP_NO_TICKET;
static const long Cryptography_HAS_ALPN;
static const long Cryptography_HAS_NEXTPROTONEG;
static const long Cryptography_HAS_SET_CERT_CB;

static const long SSL_FILETYPE_PEM;
static const long SSL_FILETYPE_ASN1;
static const long SSL_ERROR_NONE;
static const long SSL_ERROR_ZERO_RETURN;
static const long SSL_ERROR_WANT_READ;
static const long SSL_ERROR_WANT_WRITE;
static const long SSL_ERROR_WANT_X509_LOOKUP;
static const long SSL_ERROR_WANT_CONNECT;
static const long SSL_ERROR_SYSCALL;
static const long SSL_ERROR_SSL;
static const long SSL_SENT_SHUTDOWN;
static const long SSL_RECEIVED_SHUTDOWN;
static const long SSL_OP_NO_SSLv2;
static const long SSL_OP_NO_SSLv3;
static const long SSL_OP_NO_TLSv1;
static const long SSL_OP_NO_TLSv1_1;
static const long SSL_OP_NO_TLSv1_2;
static const long SSL_OP_NO_COMPRESSION;
static const long SSL_OP_SINGLE_DH_USE;
static const long SSL_OP_EPHEMERAL_RSA;
static const long SSL_OP_MICROSOFT_SESS_ID_BUG;
static const long SSL_OP_NETSCAPE_CHALLENGE_BUG;
static const long SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG;
static const long SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG;
static const long SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER;
static const long SSL_OP_MSIE_SSLV2_RSA_PADDING;
static const long SSL_OP_SSLEAY_080_CLIENT_DH_BUG;
static const long SSL_OP_TLS_D5_BUG;
static const long SSL_OP_TLS_BLOCK_PADDING_BUG;
static const long SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS;
static const long SSL_OP_CIPHER_SERVER_PREFERENCE;
static const long SSL_OP_TLS_ROLLBACK_BUG;
static const long SSL_OP_PKCS1_CHECK_1;
static const long SSL_OP_PKCS1_CHECK_2;
static const long SSL_OP_NETSCAPE_CA_DN_BUG;
static const long SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG;
static const long SSL_OP_NO_QUERY_MTU;
static const long SSL_OP_COOKIE_EXCHANGE;
static const long SSL_OP_NO_TICKET;
static const long SSL_OP_ALL;
static const long SSL_OP_SINGLE_ECDH_USE;
static const long SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION;
static const long SSL_OP_LEGACY_SERVER_CONNECT;
static const long SSL_VERIFY_PEER;
static const long SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
static const long SSL_VERIFY_CLIENT_ONCE;
static const long SSL_VERIFY_NONE;
static const long SSL_SESS_CACHE_OFF;
static const long SSL_SESS_CACHE_CLIENT;
static const long SSL_SESS_CACHE_SERVER;
static const long SSL_SESS_CACHE_BOTH;
static const long SSL_SESS_CACHE_NO_AUTO_CLEAR;
static const long SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;
static const long SSL_SESS_CACHE_NO_INTERNAL_STORE;
static const long SSL_SESS_CACHE_NO_INTERNAL;
static const long SSL_ST_CONNECT;
static const long SSL_ST_ACCEPT;
static const long SSL_ST_MASK;
static const long SSL_ST_INIT;
static const long SSL_ST_BEFORE;
static const long SSL_ST_OK;
static const long SSL_ST_RENEGOTIATE;
static const long SSL_CB_LOOP;
static const long SSL_CB_EXIT;
static const long SSL_CB_READ;
static const long SSL_CB_WRITE;
static const long SSL_CB_ALERT;
static const long SSL_CB_READ_ALERT;
static const long SSL_CB_WRITE_ALERT;
static const long SSL_CB_ACCEPT_LOOP;
static const long SSL_CB_ACCEPT_EXIT;
static const long SSL_CB_CONNECT_LOOP;
static const long SSL_CB_CONNECT_EXIT;
static const long SSL_CB_HANDSHAKE_START;
static const long SSL_CB_HANDSHAKE_DONE;
static const long SSL_MODE_RELEASE_BUFFERS;
static const long SSL_MODE_ENABLE_PARTIAL_WRITE;
static const long SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER;
static const long SSL_MODE_AUTO_RETRY;
static const long SSL3_RANDOM_SIZE;
static const long TLS_ST_BEFORE;
static const long TLS_ST_OK;

static const long OPENSSL_NPN_NEGOTIATED;

typedef ... SSL_METHOD;
typedef ... SSL_CTX;

typedef ... SSL_SESSION;

typedef ... SSL;

static const long TLSEXT_NAMETYPE_host_name;
static const long TLSEXT_STATUSTYPE_ocsp;

typedef ... SSL_CIPHER;
typedef ... Cryptography_STACK_OF_SSL_CIPHER;
typedef ... COMP_METHOD;
"""

FUNCTIONS = """
/*  SSL */
const char *SSL_state_string_long(const SSL *);
SSL_SESSION *SSL_get1_session(SSL *);
int SSL_set_session(SSL *, SSL_SESSION *);
int SSL_get_verify_mode(const SSL *);
void SSL_set_verify(SSL *, int, int (*)(int, X509_STORE_CTX *));
void SSL_set_verify_depth(SSL *, int);
int SSL_get_verify_depth(const SSL *);
int (*SSL_get_verify_callback(const SSL *))(int, X509_STORE_CTX *);
void SSL_set_info_callback(SSL *ssl, void (*)(const SSL *, int, int));
void (*SSL_get_info_callback(const SSL *))(const SSL *, int, int);
SSL *SSL_new(SSL_CTX *);
void SSL_free(SSL *);
int SSL_set_fd(SSL *, int);
SSL_CTX *SSL_get_SSL_CTX(const SSL *);
SSL_CTX *SSL_set_SSL_CTX(SSL *, SSL_CTX *);
BIO *SSL_get_rbio(const SSL *);
BIO *SSL_get_wbio(const SSL *);
void SSL_set_bio(SSL *, BIO *, BIO *);
void SSL_set_connect_state(SSL *);
void SSL_set_accept_state(SSL *);
void SSL_set_shutdown(SSL *, int);
int SSL_get_shutdown(const SSL *);
int SSL_pending(const SSL *);
int SSL_write(SSL *, const void *, int);
int SSL_read(SSL *, void *, int);
int SSL_peek(SSL *, void *, int);
X509 *SSL_get_peer_certificate(const SSL *);
int SSL_get_ex_data_X509_STORE_CTX_idx(void);

int SSL_use_certificate(SSL *, X509 *);
int SSL_use_certificate_ASN1(SSL *, const unsigned char *, int);
int SSL_use_certificate_file(SSL *, const char *, int);
int SSL_use_PrivateKey(SSL *, EVP_PKEY *);
int SSL_use_PrivateKey_ASN1(int, SSL *, const unsigned char *, long);
int SSL_use_PrivateKey_file(SSL *, const char *, int);
int SSL_check_private_key(const SSL *);

Cryptography_STACK_OF_X509 *SSL_get_peer_cert_chain(const SSL *);
Cryptography_STACK_OF_X509_NAME *SSL_get_client_CA_list(const SSL *);

int SSL_get_error(const SSL *, int);
int SSL_do_handshake(SSL *);
int SSL_shutdown(SSL *);
int SSL_renegotiate(SSL *);
int SSL_renegotiate_pending(SSL *);
const char *SSL_get_cipher_list(const SSL *, int);
Cryptography_STACK_OF_SSL_CIPHER *SSL_get_ciphers(const SSL *);

/*  context */
void SSL_CTX_free(SSL_CTX *);
long SSL_CTX_set_timeout(SSL_CTX *, long);
int SSL_CTX_set_default_verify_paths(SSL_CTX *);
void SSL_CTX_set_verify(SSL_CTX *, int, int (*)(int, X509_STORE_CTX *));
void SSL_CTX_set_verify_depth(SSL_CTX *, int);
int (*SSL_CTX_get_verify_callback(const SSL_CTX *))(int, X509_STORE_CTX *);
int SSL_CTX_get_verify_mode(const SSL_CTX *);
int SSL_CTX_get_verify_depth(const SSL_CTX *);
int SSL_CTX_set_cipher_list(SSL_CTX *, const char *);
int SSL_CTX_load_verify_locations(SSL_CTX *, const char *, const char *);
void SSL_CTX_set_default_passwd_cb(SSL_CTX *, pem_password_cb *);
void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *, void *);
int SSL_CTX_use_certificate(SSL_CTX *, X509 *);
int SSL_CTX_use_certificate_ASN1(SSL_CTX *, int, const unsigned char *);
int SSL_CTX_use_certificate_file(SSL_CTX *, const char *, int);
int SSL_CTX_use_certificate_chain_file(SSL_CTX *, const char *);
int SSL_CTX_use_PrivateKey(SSL_CTX *, EVP_PKEY *);
int SSL_CTX_use_PrivateKey_ASN1(int, SSL_CTX *, const unsigned char *, long);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *, const char *, int);
int SSL_CTX_check_private_key(const SSL_CTX *);
void SSL_CTX_set_cert_verify_callback(SSL_CTX *,
                                      int (*)(X509_STORE_CTX *,void *),
                                      void *);
int SSL_CTX_set_session_id_context(SSL_CTX *, const unsigned char *,
                                   unsigned int);

void SSL_CTX_set_cert_store(SSL_CTX *, X509_STORE *);
X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *);
int SSL_CTX_add_client_CA(SSL_CTX *, X509 *);

void SSL_CTX_set_client_CA_list(SSL_CTX *, Cryptography_STACK_OF_X509_NAME *);

void SSL_CTX_set_info_callback(SSL_CTX *, void (*)(const SSL *, int, int));
void (*SSL_CTX_get_info_callback(SSL_CTX *))(const SSL *, int, int);

/*  SSL_SESSION */
void SSL_SESSION_free(SSL_SESSION *);

/* Information about actually used cipher */
const char *SSL_CIPHER_get_name(const SSL_CIPHER *);
int SSL_CIPHER_get_bits(const SSL_CIPHER *, int *);

size_t SSL_get_finished(const SSL *, void *, size_t);
size_t SSL_get_peer_finished(const SSL *, void *, size_t);
Cryptography_STACK_OF_X509_NAME *SSL_load_client_CA_file(const char *);

const char *SSL_get_servername(const SSL *, const int);
/* Function signature changed to const char * in 1.1.0 */
const char *SSL_CIPHER_get_version(const SSL_CIPHER *);
/* These became macros in 1.1.0 */
int SSL_library_init(void);
void SSL_load_error_strings(void);

/* these CRYPTO_EX_DATA functions became macros in 1.1.0 */
int SSL_get_ex_new_index(long, void *, CRYPTO_EX_new *, CRYPTO_EX_dup *,
                         CRYPTO_EX_free *);
int SSL_set_ex_data(SSL *, int, void *);
int SSL_CTX_get_ex_new_index(long, void *, CRYPTO_EX_new *, CRYPTO_EX_dup *,
                             CRYPTO_EX_free *);
int SSL_CTX_set_ex_data(SSL_CTX *, int, void *);

SSL_SESSION *SSL_get_session(const SSL *);
const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *, unsigned int *);

/* not a macro, but older OpenSSLs don't pass the args as const */
char *SSL_CIPHER_description(const SSL_CIPHER *, char *, int);
int SSL_SESSION_print(BIO *, const SSL_SESSION *);

/* not macros, but will be conditionally bound so can't live in functions */
const COMP_METHOD *SSL_get_current_compression(SSL *);
const COMP_METHOD *SSL_get_current_expansion(SSL *);
const char *SSL_COMP_get_name(const COMP_METHOD *);
int SSL_CTX_set_client_cert_engine(SSL_CTX *, ENGINE *);

unsigned long SSL_set_mode(SSL *, unsigned long);
unsigned long SSL_get_mode(SSL *);

unsigned long SSL_set_options(SSL *, unsigned long);
unsigned long SSL_get_options(SSL *);

void SSL_set_app_data(SSL *, char *);
char * SSL_get_app_data(SSL *);
void SSL_set_read_ahead(SSL *, int);

int SSL_want_read(const SSL *);
int SSL_want_write(const SSL *);

long SSL_total_renegotiations(SSL *);
long SSL_get_secure_renegotiation_support(SSL *);

/* Defined as unsigned long because SSL_OP_ALL is greater than signed 32-bit
   and Windows defines long as 32-bit. */
unsigned long SSL_CTX_set_options(SSL_CTX *, unsigned long);
unsigned long SSL_CTX_clear_options(SSL_CTX *, unsigned long);
unsigned long SSL_CTX_get_options(SSL_CTX *);
unsigned long SSL_CTX_set_mode(SSL_CTX *, unsigned long);
unsigned long SSL_CTX_get_mode(SSL_CTX *);
unsigned long SSL_CTX_set_session_cache_mode(SSL_CTX *, unsigned long);
unsigned long SSL_CTX_get_session_cache_mode(SSL_CTX *);
unsigned long SSL_CTX_set_tmp_dh(SSL_CTX *, DH *);
unsigned long SSL_CTX_set_tmp_ecdh(SSL_CTX *, EC_KEY *);
unsigned long SSL_CTX_add_extra_chain_cert(SSL_CTX *, X509 *);

/*- These aren't macros these functions are all const X on openssl > 1.0.x -*/

/*  methods */

/*
 * TLSv1_1 and TLSv1_2 are recent additions.  Only sufficiently new versions of
 * OpenSSL support them.
 */
const SSL_METHOD *TLSv1_1_method(void);
const SSL_METHOD *TLSv1_1_server_method(void);
const SSL_METHOD *TLSv1_1_client_method(void);

const SSL_METHOD *TLSv1_2_method(void);
const SSL_METHOD *TLSv1_2_server_method(void);
const SSL_METHOD *TLSv1_2_client_method(void);

const SSL_METHOD *SSLv3_method(void);
const SSL_METHOD *SSLv3_server_method(void);
const SSL_METHOD *SSLv3_client_method(void);

const SSL_METHOD *TLSv1_method(void);
const SSL_METHOD *TLSv1_server_method(void);
const SSL_METHOD *TLSv1_client_method(void);

const SSL_METHOD *DTLSv1_method(void);
const SSL_METHOD *DTLSv1_server_method(void);
const SSL_METHOD *DTLSv1_client_method(void);

/* Added in 1.0.2 */
const SSL_METHOD *DTLS_method(void);
const SSL_METHOD *DTLS_server_method(void);
const SSL_METHOD *DTLS_client_method(void);

const SSL_METHOD *SSLv23_method(void);
const SSL_METHOD *SSLv23_server_method(void);
const SSL_METHOD *SSLv23_client_method(void);

/*- These aren't macros these arguments are all const X on openssl > 1.0.x -*/
SSL_CTX *SSL_CTX_new(SSL_METHOD *);
long SSL_CTX_get_timeout(const SSL_CTX *);

const SSL_CIPHER *SSL_get_current_cipher(const SSL *);
const char *SSL_get_version(const SSL *);
int SSL_version(const SSL *);

void *SSL_CTX_get_ex_data(const SSL_CTX *, int);
void *SSL_get_ex_data(const SSL *, int);

void SSL_set_tlsext_host_name(SSL *, char *);
void SSL_CTX_set_tlsext_servername_callback(
    SSL_CTX *,
    int (*)(const SSL *, int *, void *));
void SSL_CTX_set_tlsext_servername_arg(
    SSL_CTX *, void *);

long SSL_set_tlsext_status_ocsp_resp(SSL *, unsigned char *, int);
long SSL_get_tlsext_status_ocsp_resp(SSL *, const unsigned char **);
long SSL_set_tlsext_status_type(SSL *, long);
long SSL_CTX_set_tlsext_status_cb(SSL_CTX *, int(*)(SSL *, void *));
long SSL_CTX_set_tlsext_status_arg(SSL_CTX *, void *);

long SSL_session_reused(SSL *);

void SSL_CTX_set_next_protos_advertised_cb(SSL_CTX *,
                                           int (*)(SSL *,
                                                   const unsigned char **,
                                                   unsigned int *,
                                                   void *),
                                           void *);
void SSL_CTX_set_next_proto_select_cb(SSL_CTX *,
                                      int (*)(SSL *,
                                              unsigned char **,
                                              unsigned char *,
                                              const unsigned char *,
                                              unsigned int,
                                              void *),
                                      void *);
int SSL_select_next_proto(unsigned char **, unsigned char *,
                          const unsigned char *, unsigned int,
                          const unsigned char *, unsigned int);
void SSL_get0_next_proto_negotiated(const SSL *,
                                    const unsigned char **, unsigned *);

int sk_SSL_CIPHER_num(Cryptography_STACK_OF_SSL_CIPHER *);
const SSL_CIPHER *sk_SSL_CIPHER_value(Cryptography_STACK_OF_SSL_CIPHER *, int);

/* ALPN APIs were introduced in OpenSSL 1.0.2.  To continue to support earlier
 * versions some special handling of these is necessary.
 */
int SSL_CTX_set_alpn_protos(SSL_CTX *, const unsigned char *, unsigned);
int SSL_set_alpn_protos(SSL *, const unsigned char *, unsigned);
void SSL_CTX_set_alpn_select_cb(SSL_CTX *,
                                int (*) (SSL *,
                                         const unsigned char **,
                                         unsigned char *,
                                         const unsigned char *,
                                         unsigned int,
                                         void *),
                                void *);
void SSL_get0_alpn_selected(const SSL *, const unsigned char **, unsigned *);

long SSL_get_server_tmp_key(SSL *, EVP_PKEY **);

/* SSL_CTX_set_cert_cb is introduced in OpenSSL 1.0.2. To continue to support
 * earlier versions some special handling of these is necessary.
 */
void SSL_CTX_set_cert_cb(SSL_CTX *, int (*)(SSL *, void *), void *);
void SSL_set_cert_cb(SSL *, int (*)(SSL *, void *), void *);

/* Added in 1.0.2 */
const SSL_METHOD *SSL_CTX_get_ssl_method(SSL_CTX *);

int SSL_SESSION_set1_id_context(SSL_SESSION *, const unsigned char *,
                                unsigned int);
/* Added in 1.1.0 for the great opaquing of structs */
size_t SSL_SESSION_get_master_key(const SSL_SESSION *, unsigned char *,
                                  size_t);
size_t SSL_get_client_random(const SSL *, unsigned char *, size_t);
size_t SSL_get_server_random(const SSL *, unsigned char *, size_t);
int SSL_export_keying_material(SSL *, unsigned char *, size_t, const char *,
                               size_t, const unsigned char *, size_t, int);

long SSL_CTX_sess_number(SSL_CTX *);
long SSL_CTX_sess_connect(SSL_CTX *);
long SSL_CTX_sess_connect_good(SSL_CTX *);
long SSL_CTX_sess_connect_renegotiate(SSL_CTX *);
long SSL_CTX_sess_accept(SSL_CTX *);
long SSL_CTX_sess_accept_good(SSL_CTX *);
long SSL_CTX_sess_accept_renegotiate(SSL_CTX *);
long SSL_CTX_sess_hits(SSL_CTX *);
long SSL_CTX_sess_cb_hits(SSL_CTX *);
long SSL_CTX_sess_misses(SSL_CTX *);
long SSL_CTX_sess_timeouts(SSL_CTX *);
long SSL_CTX_sess_cache_full(SSL_CTX *);

/* DTLS support */
long Cryptography_DTLSv1_get_timeout(SSL *, time_t *, long *);
long DTLSv1_handle_timeout(SSL *);
"""

CUSTOMIZATIONS = """
/* Added in 1.0.2 but we need it in all versions now due to the great
   opaquing. */
#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_102
/* from ssl/ssl_lib.c */
const SSL_METHOD *SSL_CTX_get_ssl_method(SSL_CTX *ctx) {
    return ctx->method;
}
#endif

/* Added in 1.1.0 in the great opaquing, but we need to define it for older
   OpenSSLs. Such is our burden. */
#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_110
/* from ssl/ssl_lib.c */
size_t SSL_get_client_random(const SSL *ssl, unsigned char *out, size_t outlen)
{
    if (outlen == 0)
        return sizeof(ssl->s3->client_random);
    if (outlen > sizeof(ssl->s3->client_random))
        outlen = sizeof(ssl->s3->client_random);
    memcpy(out, ssl->s3->client_random, outlen);
    return outlen;
}
/* Added in 1.1.0 as well */
/* from ssl/ssl_lib.c */
size_t SSL_get_server_random(const SSL *ssl, unsigned char *out, size_t outlen)
{
    if (outlen == 0)
        return sizeof(ssl->s3->server_random);
    if (outlen > sizeof(ssl->s3->server_random))
        outlen = sizeof(ssl->s3->server_random);
    memcpy(out, ssl->s3->server_random, outlen);
    return outlen;
}
/* Added in 1.1.0 as well */
/* from ssl/ssl_lib.c */
size_t SSL_SESSION_get_master_key(const SSL_SESSION *session,
                               unsigned char *out, size_t outlen)
{
    if (session->master_key_length < 0) {
        /* Should never happen */
        return 0;
    }
    if (outlen == 0)
        return session->master_key_length;
    if (outlen > (size_t)session->master_key_length)
        outlen = session->master_key_length;
    memcpy(out, session->master_key, outlen);
    return outlen;
}
#endif

static const long Cryptography_HAS_SECURE_RENEGOTIATION = 1;

/* Cryptography now compiles out all SSLv2 bindings. This exists to allow
 * clients that use it to check for SSLv2 support to keep functioning as
 * expected.
 */
static const long Cryptography_HAS_SSL2 = 0;

#ifdef OPENSSL_NO_SSL3_METHOD
static const long Cryptography_HAS_SSL3_METHOD = 0;
SSL_METHOD* (*SSLv3_method)(void) = NULL;
SSL_METHOD* (*SSLv3_client_method)(void) = NULL;
SSL_METHOD* (*SSLv3_server_method)(void) = NULL;
#else
static const long Cryptography_HAS_SSL3_METHOD = 1;
#endif

static const long Cryptography_HAS_TLSEXT_HOSTNAME = 1;
static const long Cryptography_HAS_TLSEXT_STATUS_REQ_CB = 1;
static const long Cryptography_HAS_STATUS_REQ_OCSP_RESP = 1;
static const long Cryptography_HAS_TLSEXT_STATUS_REQ_TYPE = 1;
static const long Cryptography_HAS_RELEASE_BUFFERS = 1;
static const long Cryptography_HAS_OP_NO_COMPRESSION = 1;
static const long Cryptography_HAS_TLSv1_1 = 1;
static const long Cryptography_HAS_TLSv1_2 = 1;
static const long Cryptography_HAS_SSL_OP_MSIE_SSLV2_RSA_PADDING = 1;
static const long Cryptography_HAS_SSL_OP_NO_TICKET = 1;
static const long Cryptography_HAS_SSL_SET_SSL_CTX = 1;
static const long Cryptography_HAS_NEXTPROTONEG = 1;

/* ALPN was added in OpenSSL 1.0.2. */
#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_102 && !CRYPTOGRAPHY_IS_LIBRESSL
int (*SSL_CTX_set_alpn_protos)(SSL_CTX *,
                               const unsigned char *,
                               unsigned) = NULL;
int (*SSL_set_alpn_protos)(SSL *, const unsigned char *, unsigned) = NULL;
void (*SSL_CTX_set_alpn_select_cb)(SSL_CTX *,
                                   int (*) (SSL *,
                                            const unsigned char **,
                                            unsigned char *,
                                            const unsigned char *,
                                            unsigned int,
                                            void *),
                                   void *) = NULL;
void (*SSL_get0_alpn_selected)(const SSL *,
                               const unsigned char **,
                               unsigned *) = NULL;
static const long Cryptography_HAS_ALPN = 0;
#else
static const long Cryptography_HAS_ALPN = 1;
#endif

/* SSL_CTX_set_cert_cb was added in OpenSSL 1.0.2. */
#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_102
void (*SSL_CTX_set_cert_cb)(SSL_CTX *, int (*)(SSL *, void *), void *) = NULL;
void (*SSL_set_cert_cb)(SSL *, int (*)(SSL *, void *), void *) = NULL;
static const long Cryptography_HAS_SET_CERT_CB = 0;
#else
static const long Cryptography_HAS_SET_CERT_CB = 1;
#endif


/* In OpenSSL 1.0.2i+ the handling of COMP_METHOD when OPENSSL_NO_COMP was
   changed and we no longer need to typedef void */
#if (defined(OPENSSL_NO_COMP) && CRYPTOGRAPHY_OPENSSL_LESS_THAN_102I) || \
    CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_COMPRESSION = 0;
typedef void COMP_METHOD;
#else
static const long Cryptography_HAS_COMPRESSION = 1;
#endif

#if defined(SSL_CTRL_GET_SERVER_TMP_KEY)
static const long Cryptography_HAS_GET_SERVER_TMP_KEY = 1;
#else
static const long Cryptography_HAS_GET_SERVER_TMP_KEY = 0;
long (*SSL_get_server_tmp_key)(SSL *, EVP_PKEY **) = NULL;
#endif

static const long Cryptography_HAS_SSL_CTX_SET_CLIENT_CERT_ENGINE = 1;

static const long Cryptography_HAS_SSL_CTX_CLEAR_OPTIONS = 1;

/* in OpenSSL 1.1.0 the SSL_ST values were renamed to TLS_ST and several were
   removed */
#if CRYPTOGRAPHY_OPENSSL_LESS_THAN_110
static const long Cryptography_HAS_SSL_ST = 1;
#else
static const long Cryptography_HAS_SSL_ST = 0;
static const long SSL_ST_BEFORE = 0;
static const long SSL_ST_OK = 0;
static const long SSL_ST_INIT = 0;
static const long SSL_ST_RENEGOTIATE = 0;
#endif
#if CRYPTOGRAPHY_OPENSSL_110_OR_GREATER
static const long Cryptography_HAS_TLS_ST = 1;
#else
static const long Cryptography_HAS_TLS_ST = 0;
static const long TLS_ST_BEFORE = 0;
static const long TLS_ST_OK = 0;
#endif

#if defined(OPENSSL_NO_DTLS) || CRYPTOGRAPHY_OPENSSL_LESS_THAN_102
static const long Cryptography_HAS_GENERIC_DTLS_METHOD = 0;
const SSL_METHOD *(*DTLS_method)(void) = NULL;
const SSL_METHOD *(*DTLS_server_method)(void) = NULL;
const SSL_METHOD *(*DTLS_client_method)(void) = NULL;
#else
static const long Cryptography_HAS_GENERIC_DTLS_METHOD = 1;
#endif

static const long Cryptography_HAS_DTLS = 1;
/* Wrap DTLSv1_get_timeout to avoid cffi to handle a 'struct timeval'. */
long Cryptography_DTLSv1_get_timeout(SSL *ssl, time_t *ptv_sec,
                                     long *ptv_usec) {
    struct timeval tv = { 0 };
    long r = DTLSv1_get_timeout(ssl, &tv);

    if (r == 1) {
        if (ptv_sec) {
            *ptv_sec = tv.tv_sec;
        }

        if (ptv_usec) {
            *ptv_usec = tv.tv_usec;
        }
    }

    return r;
}
"""
