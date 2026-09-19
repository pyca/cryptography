#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/rand.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/ssl.h>
#include <openssl/buffer.h>
#if defined(OPENSSL_IS_AWSLC)
#define OB_BACKEND_CODE 3
#elif defined(OPENSSL_IS_BORINGSSL)
#define OB_BACKEND_CODE 2
#elif defined(LIBRESSL_VERSION_NUMBER)
#define OB_BACKEND_CODE 1
#else
#define OB_BACKEND_CODE 0
#endif
#if defined(OPENSSL_IS_AWSLC)
#include <openssl/experimental/kem_deterministic_api.h>
#elif defined(OPENSSL_IS_BORINGSSL)
#include <openssl/mldsa.h>
#include <openssl/bytestring.h>
void OB_CBS_init(CBS *cbs, const unsigned char *data, size_t length);
#endif
#if defined(LIBRESSL_VERSION_NUMBER)
#include <openssl/poly1305.h>
#endif
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
#include <openssl/aead.h>
#include <openssl/poly1305.h>
#else
#if !defined(LIBRESSL_VERSION_NUMBER)
#include <openssl/provider.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#endif
#endif

int OB_md_size(const EVP_MD *md);
int OB_md_block_size(const EVP_MD *md);
int OB_md_is_xof(const EVP_MD *md);
int OB_err_lib(unsigned long code);
int OB_err_reason(unsigned long code);
int OB_cipher_key_size(const EVP_CIPHER *cipher);
int OB_cipher_iv_size(const EVP_CIPHER *cipher);
int OB_cipher_block_size(const EVP_CIPHER *cipher);
int OB_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int OB_rsa_padding(EVP_PKEY_CTX *ctx, int padding);
int OB_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int OB_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md);
int OB_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int length);
int OB_rsa_oaep_label(EVP_PKEY_CTX *ctx, const unsigned char *label, int length);

int OB_signature_nonce(EVP_PKEY_CTX *ctx, unsigned int nonce_type);

void OB_free(void *p);
void OB_clear_memory_bio(BIO *bio);
size_t OB_bio_pending(BIO *bio);
STACK_OF(X509) *OB_x509_stack_new(void);
int OB_x509_stack_push(STACK_OF(X509) *stack, X509 *cert);
ASN1_TIME *OB_x509_not_before(X509 *cert);
ASN1_TIME *OB_x509_not_after(X509 *cert);
int OB_pkey_id(const EVP_PKEY *key);
int OB_pkey_bits(const EVP_PKEY *key);
unsigned long OB_x509_name_hash(X509_NAME *name);

uint64_t OB_tls_context_set_options(SSL_CTX *ctx, uint64_t options);
uint64_t OB_tls_set_options(SSL *ssl, uint64_t options);
uint64_t OB_tls_context_set_mode(SSL_CTX *ctx, uint64_t mode);
uint64_t OB_tls_context_clear_mode(SSL_CTX *ctx, uint64_t mode);
uint64_t OB_tls_set_mode(SSL *ssl, uint64_t mode);
int OB_tls_context_min_version(SSL_CTX *ctx, int version);
int OB_tls_context_max_version(SSL_CTX *ctx, int version);
int OB_tls_context_add_chain_cert(SSL_CTX *ctx, X509 *cert);
long OB_tls_context_cache_mode(SSL_CTX *ctx);
long OB_tls_context_set_cache_mode(SSL_CTX *ctx, long mode);
long OB_tls_context_timeout(SSL_CTX *ctx);
void OB_bio_eof_return(BIO *bio, int value);
int OB_bio_retry(BIO *bio);
int OB_tls_set_server_name(SSL *ssl, const char *name);
int OB_dup_socket(int descriptor);
void OB_close_socket(int descriptor);
void OB_clear_errno(void);
int OB_get_errno(void);
void OB_set_errno(int value);
void OB_restore_error(unsigned long code);
int OB_has_implicit_rsa_rejection(void);
/* Bounded fixed-code fixture for consumers' error-translation tests. */
unsigned long OB_test_queue_errors(unsigned int count);
void OB_bio_clear_retry(BIO *bio);
void OB_bio_retry_read(BIO *bio);
void OB_bio_retry_write(BIO *bio);
int OB_dgram_control_kind(int command);
int OB_dtls_set_mtu(SSL *ssl, unsigned int mtu);
int OB_dtls_timeout(SSL *ssl, uint64_t *microseconds);
int OB_dtls_handle_timeout(SSL *ssl);
int OB_dtls_listen(SSL *ssl, unsigned int mtu);
size_t OB_dtls_data_mtu(SSL *ssl, unsigned int mtu);
int OB_tls_handshake_complete(SSL *ssl);
size_t OB_tls_constant_count(void);
const char *OB_tls_constant_name(size_t index);
int64_t OB_tls_constant_value(size_t index);
int OB_tls_context_groups(SSL_CTX *ctx, const char *groups);
int OB_tls_context_dh(SSL_CTX *ctx, DH *parameters);
int OB_tls_context_srtp(SSL_CTX *ctx, const char *profiles);
const char *OB_tls_srtp(SSL *ssl);
const char *OB_tls_group(SSL *ssl);
X509 *OB_tls_peer_certificate(SSL *ssl);
const STACK_OF(X509) *OB_tls_verified_chain(SSL *ssl);
size_t OB_x509_name_stack_len(const STACK_OF(X509_NAME) *stack);
X509_NAME *OB_x509_name_stack_get(const STACK_OF(X509_NAME) *stack, size_t index);
STACK_OF(X509_NAME) *OB_x509_name_stack_new(void);
int OB_x509_name_stack_push(STACK_OF(X509_NAME) *stack, X509_NAME *name);
void OB_x509_name_stack_free(STACK_OF(X509_NAME) *stack);
int OB_tls_renegotiate(SSL *ssl);
int OB_tls_renegotiate_pending(SSL *ssl);
long OB_tls_total_renegotiations(SSL *ssl);
int OB_tls_ex_index(void);
int OB_tls_context_sni_callback(SSL_CTX *ctx, int (*callback)(SSL *, int *, void *));
int OB_tls_context_ocsp_callback(SSL_CTX *ctx, int (*callback)(SSL *, void *));
size_t OB_tls_ocsp_response(SSL *ssl, const unsigned char **out);
int OB_tls_set_ocsp_response(SSL *ssl, const unsigned char *data, size_t length);
int OB_tls_request_ocsp(SSL *ssl);
int OB_tls_is_server(SSL *ssl);
int OB_tls_context_cookie_callbacks(SSL_CTX *ctx,
    int (*generate)(SSL *, unsigned char *, unsigned int *),
    int (*verify)(SSL *, const unsigned char *, unsigned int));

size_t OB_x509_stack_len(const STACK_OF(X509) *stack);
X509 *OB_x509_stack_get(const STACK_OF(X509) *stack, size_t index);
void OB_x509_stack_free(STACK_OF(X509) *stack);
#if OB_BACKEND_CODE == 2 || OB_BACKEND_CODE == 3
int OB_private_key_pkcs8(const EVP_PKEY *key, unsigned char *output, size_t capacity, size_t *length);
#endif
#if OB_BACKEND_CODE == 0 || OB_BACKEND_CODE == 1
int OB_pkcs7_kind(const PKCS7 *p7);
const STACK_OF(X509) *OB_pkcs7_certificates(const PKCS7 *p7);
#endif

#if OB_BACKEND_CODE == 0
int OB_pkey_from_seed(EVP_PKEY_CTX *ctx, EVP_PKEY **key, void *seed, size_t length);
int OB_mldsa_parameters(EVP_PKEY_CTX *ctx, void *context, size_t length, unsigned int mu);
int OB_argon2_derive(EVP_KDF_CTX *ctx, unsigned char *out, size_t length,
    void *password, size_t password_length, void *salt, size_t salt_length,
    void *ad, size_t ad_length, void *secret, size_t secret_length,
    uint32_t iterations, uint32_t lanes, uint32_t memory, uint32_t size);
#endif
