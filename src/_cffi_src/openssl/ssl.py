# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.


INCLUDES = """
#include <openssl/ssl.h>

typedef STACK_OF(SSL_CIPHER) Cryptography_STACK_OF_SSL_CIPHER;
"""

TYPES = """
static const long Cryptography_HAS_SSL_ST;
static const long Cryptography_HAS_TLS_ST;
static const long Cryptography_HAS_SSL3_METHOD;
static const long Cryptography_HAS_TLSv1_1;
static const long Cryptography_HAS_TLSv1_2;
static const long Cryptography_HAS_TLSv1_3_FUNCTIONS;
static const long Cryptography_HAS_SECURE_RENEGOTIATION;
static const long Cryptography_HAS_SSL_CTX_CLEAR_OPTIONS;
static const long Cryptography_HAS_DTLS;
static const long Cryptography_HAS_SIGALGS;
static const long Cryptography_HAS_PSK;
static const long Cryptography_HAS_PSK_TLSv1_3;
static const long Cryptography_HAS_VERIFIED_CHAIN;
static const long Cryptography_HAS_KEYLOG;
static const long Cryptography_HAS_TLSEXT_HOSTNAME;
static const long Cryptography_HAS_SSL_COOKIE;

/* Internally invented symbol to tell us if SSL_MODE_RELEASE_BUFFERS is
 * supported
 */
static const long Cryptography_HAS_RELEASE_BUFFERS;

/* Internally invented symbol to tell us if SSL_OP_NO_COMPRESSION is
 * supported
 */
static const long Cryptography_HAS_OP_NO_COMPRESSION;
static const long Cryptography_HAS_OP_NO_RENEGOTIATION;
static const long Cryptography_HAS_SSL_OP_MSIE_SSLV2_RSA_PADDING;
static const long Cryptography_HAS_SSL_SET_SSL_CTX;
static const long Cryptography_HAS_SSL_OP_NO_TICKET;
static const long Cryptography_HAS_SSL_OP_IGNORE_UNEXPECTED_EOF;
static const long Cryptography_HAS_ALPN;
static const long Cryptography_HAS_NEXTPROTONEG;
static const long Cryptography_HAS_SET_CERT_CB;
static const long Cryptography_HAS_GET_EXTMS_SUPPORT;
static const long Cryptography_HAS_CUSTOM_EXT;
static const long Cryptography_HAS_SRTP;
static const long Cryptography_HAS_DTLS_GET_DATA_MTU;

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
static const long SSL_OP_NO_TLSv1_3;
static const long SSL_OP_NO_DTLSv1;
static const long SSL_OP_NO_DTLSv1_2;
static const long SSL_OP_NO_RENEGOTIATION;
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
static const long SSL_OP_IGNORE_UNEXPECTED_EOF;
static const long SSL_VERIFY_PEER;
static const long SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
static const long SSL_VERIFY_CLIENT_ONCE;
static const long SSL_VERIFY_NONE;
static const long SSL_VERIFY_POST_HANDSHAKE;
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

static const long SSL3_VERSION;
static const long TLS1_VERSION;
static const long TLS1_1_VERSION;
static const long TLS1_2_VERSION;
static const long TLS1_3_VERSION;

typedef ... SSL_METHOD;
typedef ... SSL_CTX;

typedef ... SSL_SESSION;

typedef ... SSL;

static const long TLSEXT_NAMETYPE_host_name;
static const long TLSEXT_STATUSTYPE_ocsp;

typedef ... SSL_CIPHER;
typedef ... Cryptography_STACK_OF_SSL_CIPHER;

typedef struct {
    const char *name;
    unsigned long id;
} SRTP_PROTECTION_PROFILE;
"""

FUNCTIONS = """
/*  SSL */
const char *SSL_state_string_long(const SSL *);
SSL_SESSION *SSL_get1_session(SSL *);
int SSL_set_session(SSL *, SSL_SESSION *);
SSL *SSL_new(SSL_CTX *);
void SSL_free(SSL *);
int SSL_set_fd(SSL *, int);
SSL_CTX *SSL_set_SSL_CTX(SSL *, SSL_CTX *);
void SSL_set_bio(SSL *, BIO *, BIO *);
void SSL_set_connect_state(SSL *);
void SSL_set_accept_state(SSL *);
void SSL_set_shutdown(SSL *, int);
int SSL_get_shutdown(const SSL *);
int SSL_pending(const SSL *);
int SSL_write(SSL *, const void *, int);
int SSL_read(SSL *, void *, int);
int SSL_peek(SSL *, void *, int);
X509 *SSL_get_certificate(const SSL *);
X509 *SSL_get_peer_certificate(const SSL *);
int SSL_get_ex_data_X509_STORE_CTX_idx(void);
void SSL_set_verify(SSL *, int, int (*)(int, X509_STORE_CTX *));
int SSL_get_verify_mode(const SSL *);

long SSL_get_extms_support(SSL *);

X509_VERIFY_PARAM *SSL_get0_param(SSL *);
X509_VERIFY_PARAM *SSL_CTX_get0_param(SSL_CTX *);

Cryptography_STACK_OF_X509 *SSL_get_peer_cert_chain(const SSL *);
Cryptography_STACK_OF_X509 *SSL_get0_verified_chain(const SSL *);
Cryptography_STACK_OF_X509_NAME *SSL_get_client_CA_list(const SSL *);

int SSL_get_error(const SSL *, int);
long SSL_get_verify_result(const SSL *ssl);
int SSL_do_handshake(SSL *);
int SSL_shutdown(SSL *);
int SSL_renegotiate(SSL *);
int SSL_renegotiate_pending(SSL *);
const char *SSL_get_cipher_list(const SSL *, int);
int SSL_use_certificate(SSL *, X509 *);
int SSL_use_PrivateKey(SSL *, EVP_PKEY *);

/*  context */
void SSL_CTX_free(SSL_CTX *);
long SSL_CTX_set_timeout(SSL_CTX *, long);
int SSL_CTX_set_default_verify_paths(SSL_CTX *);
void SSL_CTX_set_verify(SSL_CTX *, int, int (*)(int, X509_STORE_CTX *));
void SSL_CTX_set_verify_depth(SSL_CTX *, int);
int SSL_CTX_get_verify_mode(const SSL_CTX *);
int SSL_CTX_get_verify_depth(const SSL_CTX *);
int SSL_CTX_set_cipher_list(SSL_CTX *, const char *);
int SSL_CTX_load_verify_locations(SSL_CTX *, const char *, const char *);
void SSL_CTX_set_default_passwd_cb(SSL_CTX *, pem_password_cb *);
void SSL_CTX_set_default_passwd_cb_userdata(SSL_CTX *, void *);
int SSL_CTX_use_certificate(SSL_CTX *, X509 *);
int SSL_CTX_use_certificate_file(SSL_CTX *, const char *, int);
int SSL_CTX_use_certificate_chain_file(SSL_CTX *, const char *);
int SSL_CTX_use_PrivateKey(SSL_CTX *, EVP_PKEY *);
int SSL_CTX_use_PrivateKey_file(SSL_CTX *, const char *, int);
int SSL_CTX_check_private_key(const SSL_CTX *);
void SSL_CTX_set_cert_verify_callback(SSL_CTX *,
                                      int (*)(X509_STORE_CTX *, void *),
                                      void *);

void SSL_CTX_set_cookie_generate_cb(SSL_CTX *,
                                    int (*)(
                                        SSL *,
                                        unsigned char *,
                                        unsigned int *
                                    ));
void SSL_CTX_set_cookie_verify_cb(SSL_CTX *,
                                    int (*)(
                                        SSL *,
                                        const unsigned char *,
                                        unsigned int
                                    ));

long SSL_CTX_get_read_ahead(SSL_CTX *);
long SSL_CTX_set_read_ahead(SSL_CTX *, long);

int SSL_CTX_use_psk_identity_hint(SSL_CTX *, const char *);
void SSL_CTX_set_psk_server_callback(SSL_CTX *,
                                     unsigned int (*)(
                                         SSL *,
                                         const char *,
                                         unsigned char *,
                                         unsigned int
                                     ));
void SSL_CTX_set_psk_client_callback(SSL_CTX *,
                                     unsigned int (*)(
                                         SSL *,
                                         const char *,
                                         char *,
                                         unsigned int,
                                         unsigned char *,
                                         unsigned int
                                     ));
void SSL_CTX_set_psk_find_session_callback(SSL_CTX *,
                                           int (*)(
                                               SSL *,
                                               const unsigned char *,
                                               size_t,
                                               SSL_SESSION **
                                           ));
void SSL_CTX_set_psk_use_session_callback(SSL_CTX *,
                                          int (*)(
                                              SSL *,
                                              const EVP_MD *,
                                              const unsigned char **,
                                              size_t *,
                                              SSL_SESSION **
                                          ));
const SSL_CIPHER *SSL_CIPHER_find(SSL *, const unsigned char *);
/* Wrap SSL_SESSION_new to avoid namespace collision. */
SSL_SESSION *Cryptography_SSL_SESSION_new(void);
int SSL_SESSION_set1_master_key(SSL_SESSION *, const unsigned char *,
                                 size_t);
int SSL_SESSION_set_cipher(SSL_SESSION *, const SSL_CIPHER *);
int SSL_SESSION_set_protocol_version(SSL_SESSION *, int);

int SSL_CTX_set_session_id_context(SSL_CTX *, const unsigned char *,
                                   unsigned int);

void SSL_CTX_set_cert_store(SSL_CTX *, X509_STORE *);
X509_STORE *SSL_CTX_get_cert_store(const SSL_CTX *);
int SSL_CTX_add_client_CA(SSL_CTX *, X509 *);

void SSL_CTX_set_client_CA_list(SSL_CTX *, Cryptography_STACK_OF_X509_NAME *);

void SSL_CTX_set_info_callback(SSL_CTX *, void (*)(const SSL *, int, int));
void (*SSL_CTX_get_info_callback(SSL_CTX *))(const SSL *, int, int);

void SSL_CTX_set_keylog_callback(SSL_CTX *,
                                 void (*)(const SSL *, const char *));
void (*SSL_CTX_get_keylog_callback(SSL_CTX *))(const SSL *, const char *);

long SSL_CTX_set1_sigalgs_list(SSL_CTX *, const char *);

/*  SSL_SESSION */
void SSL_SESSION_free(SSL_SESSION *);

/* Information about actually used cipher */
const char *SSL_CIPHER_get_name(const SSL_CIPHER *);
int SSL_CIPHER_get_bits(const SSL_CIPHER *, int *);
/* the modern signature of this is uint32_t, but older openssl declared it
   as unsigned long. To make our compiler flags happy we'll declare it as a
   64-bit wide value, which should always be safe */
uint64_t SSL_CIPHER_get_id(const SSL_CIPHER *);
int SSL_CIPHER_is_aead(const SSL_CIPHER *);
int SSL_CIPHER_get_cipher_nid(const SSL_CIPHER *);
int SSL_CIPHER_get_digest_nid(const SSL_CIPHER *);
int SSL_CIPHER_get_kx_nid(const SSL_CIPHER *);
int SSL_CIPHER_get_auth_nid(const SSL_CIPHER *);

size_t SSL_get_finished(const SSL *, void *, size_t);
size_t SSL_get_peer_finished(const SSL *, void *, size_t);
Cryptography_STACK_OF_X509_NAME *SSL_load_client_CA_file(const char *);

const char *SSL_get_servername(const SSL *, const int);
const char *SSL_CIPHER_get_version(const SSL_CIPHER *);

SSL_SESSION *SSL_get_session(const SSL *);
const unsigned char *SSL_SESSION_get_id(const SSL_SESSION *, unsigned int *);
long SSL_SESSION_get_time(const SSL_SESSION *);
long SSL_SESSION_get_timeout(const SSL_SESSION *);
int SSL_SESSION_has_ticket(const SSL_SESSION *);
long SSL_SESSION_get_ticket_lifetime_hint(const SSL_SESSION *);

unsigned long SSL_set_mode(SSL *, unsigned long);
unsigned long SSL_clear_mode(SSL *, unsigned long);
unsigned long SSL_get_mode(SSL *);

unsigned long SSL_set_options(SSL *, unsigned long);
unsigned long SSL_get_options(SSL *);

int SSL_want_read(const SSL *);
int SSL_want_write(const SSL *);

long SSL_total_renegotiations(SSL *);
long SSL_get_secure_renegotiation_support(SSL *);

long SSL_CTX_set_min_proto_version(SSL_CTX *, int);
long SSL_CTX_set_max_proto_version(SSL_CTX *, int);
long SSL_set_min_proto_version(SSL *, int);
long SSL_set_max_proto_version(SSL *, int);

long SSL_CTX_get_min_proto_version(SSL_CTX *);
long SSL_CTX_get_max_proto_version(SSL_CTX *);
long SSL_get_min_proto_version(SSL *);
long SSL_get_max_proto_version(SSL *);

/* Defined as unsigned long because SSL_OP_ALL is greater than signed 32-bit
   and Windows defines long as 32-bit. */
unsigned long SSL_CTX_set_options(SSL_CTX *, unsigned long);
unsigned long SSL_CTX_clear_options(SSL_CTX *, unsigned long);
unsigned long SSL_CTX_get_options(SSL_CTX *);
unsigned long SSL_CTX_set_mode(SSL_CTX *, unsigned long);
unsigned long SSL_CTX_clear_mode(SSL_CTX *, unsigned long);
unsigned long SSL_CTX_get_mode(SSL_CTX *);
unsigned long SSL_CTX_set_session_cache_mode(SSL_CTX *, unsigned long);
unsigned long SSL_CTX_get_session_cache_mode(SSL_CTX *);
unsigned long SSL_CTX_set_tmp_dh(SSL_CTX *, DH *);
unsigned long SSL_CTX_set_tmp_ecdh(SSL_CTX *, EC_KEY *);
unsigned long SSL_CTX_add_extra_chain_cert(SSL_CTX *, X509 *);

const SSL_METHOD *DTLS_method(void);
const SSL_METHOD *DTLS_server_method(void);
const SSL_METHOD *DTLS_client_method(void);

const SSL_METHOD *SSLv23_method(void);
const SSL_METHOD *SSLv23_server_method(void);
const SSL_METHOD *SSLv23_client_method(void);

const SSL_METHOD *TLS_method(void);
const SSL_METHOD *TLS_server_method(void);
const SSL_METHOD *TLS_client_method(void);

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
    int (*)(SSL *, int *, void *));
void SSL_CTX_set_tlsext_servername_arg(
    SSL_CTX *, void *);

long SSL_set_tlsext_status_ocsp_resp(SSL *, unsigned char *, int);
long SSL_get_tlsext_status_ocsp_resp(SSL *, const unsigned char **);
long SSL_set_tlsext_status_type(SSL *, long);
long SSL_CTX_set_tlsext_status_cb(SSL_CTX *, int(*)(SSL *, void *));
long SSL_CTX_set_tlsext_status_arg(SSL_CTX *, void *);

int SSL_CTX_set_tlsext_use_srtp(SSL_CTX *, const char *);
int SSL_set_tlsext_use_srtp(SSL *, const char *);
SRTP_PROTECTION_PROFILE *SSL_get_selected_srtp_profile(SSL *);

long SSL_session_reused(SSL *);

int SSL_select_next_proto(unsigned char **, unsigned char *,
                          const unsigned char *, unsigned int,
                          const unsigned char *, unsigned int);

int sk_SSL_CIPHER_num(Cryptography_STACK_OF_SSL_CIPHER *);
const SSL_CIPHER *sk_SSL_CIPHER_value(Cryptography_STACK_OF_SSL_CIPHER *, int);

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

void SSL_CTX_set_cert_cb(SSL_CTX *, int (*)(SSL *, void *), void *);
void SSL_set_cert_cb(SSL *, int (*)(SSL *, void *), void *);

int SSL_SESSION_set1_id_context(SSL_SESSION *, const unsigned char *,
                                unsigned int);
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
long DTLS_set_link_mtu(SSL *, long);
long DTLS_get_link_min_mtu(SSL *);
long SSL_set_mtu(SSL *, long);
int DTLSv1_listen(SSL *, BIO_ADDR *);
size_t DTLS_get_data_mtu(SSL *);


/* Custom extensions. */
typedef int (*custom_ext_add_cb)(SSL *, unsigned int,
                                 const unsigned char **,
                                 size_t *, int *,
                                 void *);

typedef void (*custom_ext_free_cb)(SSL *, unsigned int,
                                   const unsigned char *,
                                   void *);

typedef int (*custom_ext_parse_cb)(SSL *, unsigned int,
                                   const unsigned char *,
                                   size_t, int *,
                                   void *);

int SSL_CTX_add_client_custom_ext(SSL_CTX *, unsigned int,
                                  custom_ext_add_cb,
                                  custom_ext_free_cb, void *,
                                  custom_ext_parse_cb,
                                  void *);

int SSL_CTX_add_server_custom_ext(SSL_CTX *, unsigned int,
                                  custom_ext_add_cb,
                                  custom_ext_free_cb, void *,
                                  custom_ext_parse_cb,
                                  void *);

int SSL_extension_supported(unsigned int);

int SSL_CTX_set_ciphersuites(SSL_CTX *, const char *);
int SSL_verify_client_post_handshake(SSL *);
void SSL_CTX_set_post_handshake_auth(SSL_CTX *, int);
void SSL_set_post_handshake_auth(SSL *, int);

uint32_t SSL_SESSION_get_max_early_data(const SSL_SESSION *);
int SSL_write_early_data(SSL *, const void *, size_t, size_t *);
int SSL_read_early_data(SSL *, void *, size_t, size_t *);
int SSL_CTX_set_max_early_data(SSL_CTX *, uint32_t);

/*
  Added as an advanced user escape hatch. This symbol is tied to
  engine support but is declared in ssl.h
*/
int SSL_CTX_set_client_cert_engine(SSL_CTX *, ENGINE *);
"""

CUSTOMIZATIONS = """
// This symbol is being preserved because removing it will break users with
// pyOpenSSL < 19.1 and pip < 20.x. We need to leave this in place until those
// users have upgraded. PersistentlyDeprecated2020
static const long Cryptography_HAS_TLSEXT_HOSTNAME = 1;

#ifdef OPENSSL_NO_ENGINE
int (*SSL_CTX_set_client_cert_engine)(SSL_CTX *, ENGINE *) = NULL;
#endif

#if CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_VERIFIED_CHAIN = 0;
Cryptography_STACK_OF_X509 *(*SSL_get0_verified_chain)(const SSL *) = NULL;
#else
static const long Cryptography_HAS_VERIFIED_CHAIN = 1;
#endif

static const long Cryptography_HAS_KEYLOG = 1;
static const long Cryptography_HAS_SECURE_RENEGOTIATION = 1;

#ifdef OPENSSL_NO_SSL3_METHOD
static const long Cryptography_HAS_SSL3_METHOD = 0;
SSL_METHOD* (*SSLv3_method)(void) = NULL;
SSL_METHOD* (*SSLv3_client_method)(void) = NULL;
SSL_METHOD* (*SSLv3_server_method)(void) = NULL;
#else
static const long Cryptography_HAS_SSL3_METHOD = 1;
#endif

static const long Cryptography_HAS_RELEASE_BUFFERS = 1;
static const long Cryptography_HAS_OP_NO_COMPRESSION = 1;
static const long Cryptography_HAS_TLSv1_1 = 1;
static const long Cryptography_HAS_TLSv1_2 = 1;
static const long Cryptography_HAS_SSL_OP_MSIE_SSLV2_RSA_PADDING = 1;
static const long Cryptography_HAS_SSL_OP_NO_TICKET = 1;
static const long Cryptography_HAS_SSL_SET_SSL_CTX = 1;
static const long Cryptography_HAS_NEXTPROTONEG = 0;
static const long Cryptography_HAS_ALPN = 1;

#ifdef SSL_OP_NO_RENEGOTIATION
static const long Cryptography_HAS_OP_NO_RENEGOTIATION = 1;
#else
static const long Cryptography_HAS_OP_NO_RENEGOTIATION = 0;
static const long SSL_OP_NO_RENEGOTIATION = 0;
#endif

#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
static const long Cryptography_HAS_SSL_OP_IGNORE_UNEXPECTED_EOF = 1;
#else
static const long Cryptography_HAS_SSL_OP_IGNORE_UNEXPECTED_EOF = 0;
static const long SSL_OP_IGNORE_UNEXPECTED_EOF = 1;
#endif

#if CRYPTOGRAPHY_IS_LIBRESSL
void (*SSL_CTX_set_cert_cb)(SSL_CTX *, int (*)(SSL *, void *), void *) = NULL;
void (*SSL_set_cert_cb)(SSL *, int (*)(SSL *, void *), void *) = NULL;
static const long Cryptography_HAS_SET_CERT_CB = 0;

long (*SSL_get_extms_support)(SSL *) = NULL;
static const long Cryptography_HAS_GET_EXTMS_SUPPORT = 0;
#else
static const long Cryptography_HAS_SET_CERT_CB = 1;
static const long Cryptography_HAS_GET_EXTMS_SUPPORT = 1;
#endif

static const long Cryptography_HAS_SSL_CTX_CLEAR_OPTIONS = 1;

/* in OpenSSL 1.1.0 the SSL_ST values were renamed to TLS_ST and several were
   removed */
#if CRYPTOGRAPHY_IS_LIBRESSL || CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_SSL_ST = 1;
#else
static const long Cryptography_HAS_SSL_ST = 0;
static const long SSL_ST_BEFORE = 0;
static const long SSL_ST_OK = 0;
static const long SSL_ST_INIT = 0;
static const long SSL_ST_RENEGOTIATE = 0;
#endif
#if !CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_TLS_ST = 1;
#else
static const long Cryptography_HAS_TLS_ST = 0;
static const long TLS_ST_BEFORE = 0;
static const long TLS_ST_OK = 0;
#endif

#if CRYPTOGRAPHY_IS_LIBRESSL || CRYPTOGRAPHY_IS_BORINGSSL
long (*DTLS_set_link_mtu)(SSL *, long) = NULL;
long (*DTLS_get_link_min_mtu)(SSL *) = NULL;
#endif

#if CRYPTOGRAPHY_IS_LIBRESSL || CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_DTLS_GET_DATA_MTU = 0;
size_t (*DTLS_get_data_mtu)(SSL *) = NULL;
#else
static const long Cryptography_HAS_DTLS_GET_DATA_MTU = 1;
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

#if CRYPTOGRAPHY_IS_LIBRESSL
static const long Cryptography_HAS_SIGALGS = 0;
const long (*SSL_CTX_set1_sigalgs_list)(SSL_CTX *, const char *) = NULL;
#else
static const long Cryptography_HAS_SIGALGS = 1;
#endif

#if CRYPTOGRAPHY_IS_LIBRESSL || defined(OPENSSL_NO_PSK)
static const long Cryptography_HAS_PSK = 0;
int (*SSL_CTX_use_psk_identity_hint)(SSL_CTX *, const char *) = NULL;
void (*SSL_CTX_set_psk_server_callback)(SSL_CTX *,
                                        unsigned int (*)(
                                            SSL *,
                                            const char *,
                                            unsigned char *,
                                            unsigned int
                                        )) = NULL;
void (*SSL_CTX_set_psk_client_callback)(SSL_CTX *,
                                        unsigned int (*)(
                                            SSL *,
                                            const char *,
                                            char *,
                                            unsigned int,
                                            unsigned char *,
                                            unsigned int
                                        )) = NULL;
#else
static const long Cryptography_HAS_PSK = 1;
#endif

#if !CRYPTOGRAPHY_IS_LIBRESSL && !CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_CUSTOM_EXT = 1;
#else
static const long Cryptography_HAS_CUSTOM_EXT = 0;
typedef int (*custom_ext_add_cb)(SSL *, unsigned int,
                                 const unsigned char **,
                                 size_t *, int *,
                                 void *);
typedef void (*custom_ext_free_cb)(SSL *, unsigned int,
                                   const unsigned char *,
                                   void *);
typedef int (*custom_ext_parse_cb)(SSL *, unsigned int,
                                   const unsigned char *,
                                   size_t, int *,
                                   void *);
int (*SSL_CTX_add_client_custom_ext)(SSL_CTX *, unsigned int,
                                     custom_ext_add_cb,
                                     custom_ext_free_cb, void *,
                                     custom_ext_parse_cb,
                                     void *) = NULL;
int (*SSL_CTX_add_server_custom_ext)(SSL_CTX *, unsigned int,
                                     custom_ext_add_cb,
                                     custom_ext_free_cb, void *,
                                     custom_ext_parse_cb,
                                     void *) = NULL;
int (*SSL_extension_supported)(unsigned int) = NULL;
#endif

#ifndef OPENSSL_NO_SRTP
static const long Cryptography_HAS_SRTP = 1;
#else
static const long Cryptography_HAS_SRTP = 0;
int (*SSL_CTX_set_tlsext_use_srtp)(SSL_CTX *, const char *) = NULL;
int (*SSL_set_tlsext_use_srtp)(SSL *, const char *) = NULL;
SRTP_PROTECTION_PROFILE * (*SSL_get_selected_srtp_profile)(SSL *) = NULL;
#endif

#if CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_TLSv1_3_FUNCTIONS = 0;

static const long SSL_VERIFY_POST_HANDSHAKE = 0;
int (*SSL_CTX_set_ciphersuites)(SSL_CTX *, const char *) = NULL;
int (*SSL_verify_client_post_handshake)(SSL *) = NULL;
void (*SSL_CTX_set_post_handshake_auth)(SSL_CTX *, int) = NULL;
void (*SSL_set_post_handshake_auth)(SSL *, int) = NULL;
uint32_t (*SSL_SESSION_get_max_early_data)(const SSL_SESSION *) = NULL;
int (*SSL_write_early_data)(SSL *, const void *, size_t, size_t *) = NULL;
int (*SSL_read_early_data)(SSL *, void *, size_t, size_t *) = NULL;
int (*SSL_CTX_set_max_early_data)(SSL_CTX *, uint32_t) = NULL;
#else
static const long Cryptography_HAS_TLSv1_3_FUNCTIONS = 1;
#endif

#if CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_SSL_COOKIE = 0;

static const long SSL_OP_COOKIE_EXCHANGE = 0;
int (*DTLSv1_listen)(SSL *, BIO_ADDR *) = NULL;
void (*SSL_CTX_set_cookie_generate_cb)(SSL_CTX *,
                                       int (*)(
                                           SSL *,
                                           unsigned char *,
                                           unsigned int *
                                       )) = NULL;
void (*SSL_CTX_set_cookie_verify_cb)(SSL_CTX *,
                                       int (*)(
                                           SSL *,
                                           const unsigned char *,
                                           unsigned int
                                       )) = NULL;
#else
static const long Cryptography_HAS_SSL_COOKIE = 1;
#endif
#if CRYPTOGRAPHY_IS_LIBRESSL || CRYPTOGRAPHY_IS_BORINGSSL
static const long Cryptography_HAS_PSK_TLSv1_3 = 0;
void (*SSL_CTX_set_psk_find_session_callback)(SSL_CTX *,
                                           int (*)(
                                               SSL *,
                                               const unsigned char *,
                                               size_t,
                                               SSL_SESSION **
                                           )) = NULL;
void (*SSL_CTX_set_psk_use_session_callback)(SSL_CTX *,
                                          int (*)(
                                              SSL *,
                                              const EVP_MD *,
                                              const unsigned char **,
                                              size_t *,
                                              SSL_SESSION **
                                          )) = NULL;
#if CRYPTOGRAPHY_IS_BORINGSSL
const SSL_CIPHER *(*SSL_CIPHER_find)(SSL *, const unsigned char *) = NULL;
#endif
int (*SSL_SESSION_set1_master_key)(SSL_SESSION *, const unsigned char *,
                                   size_t) = NULL;
int (*SSL_SESSION_set_cipher)(SSL_SESSION *, const SSL_CIPHER *) = NULL;
#if !CRYPTOGRAPHY_IS_BORINGSSL
int (*SSL_SESSION_set_protocol_version)(SSL_SESSION *, int) = NULL;
#endif
SSL_SESSION *(*Cryptography_SSL_SESSION_new)(void) = NULL;
#else
static const long Cryptography_HAS_PSK_TLSv1_3 = 1;
SSL_SESSION *Cryptography_SSL_SESSION_new(void) {
    return SSL_SESSION_new();
}
#endif
"""
