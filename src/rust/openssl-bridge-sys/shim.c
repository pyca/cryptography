#include "wrapper.h"
#include <errno.h>
#include <limits.h>
#include <string.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <sys/time.h>
#endif
int OB_tls_handshake_complete(SSL *ssl) { return SSL_is_init_finished(ssl); }
int OB_tls_ex_index(void) { return SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL); }
int OB_tls_context_sni_callback(SSL_CTX *ctx, int (*callback)(SSL *, int *, void *)) {
    return SSL_CTX_set_tlsext_servername_callback(ctx, callback);
}
int OB_tls_context_ocsp_callback(SSL_CTX *ctx, int (*callback)(SSL *, void *)) {
    return SSL_CTX_set_tlsext_status_cb(ctx, callback);
}
size_t OB_tls_ocsp_response(SSL *ssl, const unsigned char **out) {
#if OB_BACKEND_CODE == 2 || OB_BACKEND_CODE == 3
    return SSL_get_tlsext_status_ocsp_resp(ssl, out);
#else
    long length = SSL_get_tlsext_status_ocsp_resp(ssl, out);
    return length < 0 ? 0 : (size_t)length;
#endif
}
int OB_tls_set_ocsp_response(SSL *ssl, const unsigned char *data, size_t length) {
    unsigned char *owned;
    int result;
    if (length == 0 || length > INT_MAX) return 0;
    owned = OPENSSL_malloc(length);
    if (owned == NULL) return 0;
    memcpy(owned, data, length);
    result = SSL_set_tlsext_status_ocsp_resp(ssl, owned, length);
    if (result != 1) OPENSSL_free(owned);
    return result;
}
int OB_tls_request_ocsp(SSL *ssl) { return SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp); }
int OB_tls_is_server(SSL *ssl) { return SSL_is_server(ssl); }
int OB_tls_context_cookie_callbacks(SSL_CTX *ctx,
    int (*generate)(SSL *, unsigned char *, unsigned int *),
    int (*verify)(SSL *, const unsigned char *, unsigned int)) {
#if OB_BACKEND_CODE == 2 || OB_BACKEND_CODE == 3
    (void)ctx; (void)generate; (void)verify; return 0;
#else
    SSL_CTX_set_cookie_generate_cb(ctx, generate);
    SSL_CTX_set_cookie_verify_cb(ctx, verify);
    return 1;
#endif
}
void OB_clear_errno(void) { errno = 0; }
int OB_get_errno(void) { return errno; }
void OB_set_errno(int value) { errno = value; }
int OB_has_implicit_rsa_rejection(void) {
#ifdef EVP_PKEY_CTRL_RSA_IMPLICIT_REJECTION
    return 1;
#else
    return 0;
#endif
}
unsigned long OB_test_queue_errors(unsigned int count) {
    if (count == 0 || count > 10) return 0;
    ERR_clear_error();
#ifdef EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH
    const int reason = EVP_R_DATA_NOT_MULTIPLE_OF_BLOCK_LENGTH;
#else
    const int reason = 0;
#endif
    for (unsigned int i = 0; i < count; i++) {
        ERR_put_error(ERR_LIB_EVP, 0, reason, "openssl-bridge diagnostic fixture", 0);
    }
    return ERR_peek_last_error();
}
void OB_restore_error(unsigned long code) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L && !defined(LIBRESSL_VERSION_NUMBER) && !defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_IS_AWSLC)
    ERR_put_error(ERR_GET_LIB(code), 0, ERR_GET_REASON(code), "openssl-bridge TLS callback", 0);
#else
    ERR_put_error(ERR_GET_LIB(code), ERR_GET_FUNC(code), ERR_GET_REASON(code), "openssl-bridge TLS callback", 0);
#endif
}
int OB_tls_context_groups(SSL_CTX *ctx, const char *groups) {
    return SSL_CTX_set1_groups_list(ctx, groups);
}
int OB_tls_context_dh(SSL_CTX *ctx, DH *parameters) {
    return SSL_CTX_set_tmp_dh(ctx, parameters);
}
int OB_tls_context_srtp(SSL_CTX *ctx, const char *profiles) {
#ifdef OPENSSL_NO_SRTP
    (void)ctx; (void)profiles; return -1;
#else
    return SSL_CTX_set_tlsext_use_srtp(ctx, profiles);
#endif
}
const char *OB_tls_srtp(SSL *ssl) {
#ifdef OPENSSL_NO_SRTP
    (void)ssl; return NULL;
#else
    const SRTP_PROTECTION_PROFILE *profile = SSL_get_selected_srtp_profile(ssl);
    return profile == NULL ? NULL : profile->name;
#endif
}
const char *OB_tls_group(SSL *ssl) {
#if OB_BACKEND_CODE == 0 && OPENSSL_VERSION_NUMBER >= 0x30200000L
    /* SSL_get0_group_name dereferences the session before a handshake has
     * created it on OpenSSL 4. Metadata callbacks also run before that point. */
    if (SSL_get_session(ssl) == NULL) return NULL;
    return SSL_get0_group_name(ssl);
#elif OB_BACKEND_CODE == 2 || OB_BACKEND_CODE == 3
    return SSL_get_group_name(SSL_get_group_id(ssl));
#else
    (void)ssl; return NULL;
#endif
}
X509 *OB_tls_peer_certificate(SSL *ssl) {
    return SSL_get_peer_certificate(ssl);
}
const STACK_OF(X509) *OB_tls_verified_chain(SSL *ssl) {
#if OB_BACKEND_CODE == 2
    /* BoringSSL exposes the constructed chain to its verification callback. */
    (void)ssl; return NULL;
#else
    return SSL_get0_verified_chain(ssl);
#endif
}
size_t OB_x509_name_stack_len(const STACK_OF(X509_NAME) *stack) {
    return stack == NULL ? 0 : (size_t)sk_X509_NAME_num(stack);
}
X509_NAME *OB_x509_name_stack_get(const STACK_OF(X509_NAME) *stack, size_t index) {
    if (index >= OB_x509_name_stack_len(stack) || index > INT_MAX) return NULL;
    return sk_X509_NAME_value(stack, (int)index);
}
STACK_OF(X509_NAME) *OB_x509_name_stack_new(void) { return sk_X509_NAME_new_null(); }
int OB_x509_name_stack_push(STACK_OF(X509_NAME) *stack, X509_NAME *name) {
    return sk_X509_NAME_push(stack, name) > 0;
}
void OB_x509_name_stack_free(STACK_OF(X509_NAME) *stack) {
    sk_X509_NAME_pop_free(stack, X509_NAME_free);
}
int OB_tls_renegotiate(SSL *ssl) {
#if OB_BACKEND_CODE == 2 || OB_BACKEND_CODE == 3
    (void)ssl; return 0;
#else
    return SSL_renegotiate(ssl);
#endif
}
int OB_tls_renegotiate_pending(SSL *ssl) { return SSL_renegotiate_pending(ssl); }
long OB_tls_total_renegotiations(SSL *ssl) { return SSL_total_renegotiations(ssl); }
#ifndef _WIN32
#include <fcntl.h>
#include <unistd.h>
#endif

uint64_t OB_tls_context_set_options(SSL_CTX *ctx, uint64_t options) { return SSL_CTX_set_options(ctx, options); }
uint64_t OB_tls_set_options(SSL *ssl, uint64_t options) { return SSL_set_options(ssl, options); }
uint64_t OB_tls_context_set_mode(SSL_CTX *ctx, uint64_t mode) { return SSL_CTX_set_mode(ctx, mode); }
uint64_t OB_tls_context_clear_mode(SSL_CTX *ctx, uint64_t mode) { return SSL_CTX_clear_mode(ctx, mode); }
uint64_t OB_tls_set_mode(SSL *ssl, uint64_t mode) { return SSL_set_mode(ssl, mode); }
int OB_tls_context_min_version(SSL_CTX *ctx, int version) { return SSL_CTX_set_min_proto_version(ctx, version); }
int OB_tls_context_max_version(SSL_CTX *ctx, int version) { return SSL_CTX_set_max_proto_version(ctx, version); }
int OB_tls_context_add_chain_cert(SSL_CTX *ctx, X509 *cert) { return SSL_CTX_add_extra_chain_cert(ctx, cert); }
long OB_tls_context_cache_mode(SSL_CTX *ctx) { return SSL_CTX_get_session_cache_mode(ctx); }
long OB_tls_context_set_cache_mode(SSL_CTX *ctx, long mode) { return SSL_CTX_set_session_cache_mode(ctx, mode); }
long OB_tls_context_timeout(SSL_CTX *ctx) { return SSL_CTX_get_timeout(ctx); }
void OB_bio_eof_return(BIO *bio, int value) { BIO_set_mem_eof_return(bio, value); }
int OB_bio_retry(BIO *bio) { return BIO_should_retry(bio); }
int OB_tls_set_server_name(SSL *ssl, const char *name) { return SSL_set_tlsext_host_name(ssl, name); }
int OB_dup_socket(int descriptor) {
#ifdef _WIN32
    (void)descriptor;
    return -1;
#else
    return fcntl(descriptor, F_DUPFD_CLOEXEC, 0);
#endif
}
void OB_close_socket(int descriptor) {
#ifndef _WIN32
    /* Do not retry close after EINTR: the descriptor may already be closed. */
    (void)close(descriptor);
#else
    (void)descriptor;
#endif
}

void OB_free(void *p) { OPENSSL_free(p); }
void OB_clear_memory_bio(BIO *bio) {
    BUF_MEM *memory = NULL;
    BIO_get_mem_ptr(bio, &memory);
    if (memory != NULL && memory->data != NULL)
        OPENSSL_cleanse(memory->data, memory->max);
}
size_t OB_bio_pending(BIO *bio) { return BIO_ctrl_pending(bio); }
STACK_OF(X509) *OB_x509_stack_new(void) { return sk_X509_new_null(); }
int OB_x509_stack_push(STACK_OF(X509) *stack, X509 *cert) {
    return sk_X509_push(stack, cert) > 0;
}
ASN1_TIME *OB_x509_not_before(X509 *cert) { return X509_getm_notBefore(cert); }
ASN1_TIME *OB_x509_not_after(X509 *cert) { return X509_getm_notAfter(cert); }
int OB_pkey_id(const EVP_PKEY *key) { return EVP_PKEY_id(key); }
int OB_pkey_bits(const EVP_PKEY *key) { return EVP_PKEY_bits(key); }
unsigned long OB_x509_name_hash(X509_NAME *name) { return X509_NAME_hash(name); }
#include <string.h>
#include <limits.h>

size_t OB_x509_stack_len(const STACK_OF(X509) *stack) {
    if (stack == NULL) return 0;
    return (size_t)sk_X509_num(stack);
}
X509 *OB_x509_stack_get(const STACK_OF(X509) *stack, size_t index) {
    if (index >= OB_x509_stack_len(stack) || index > INT_MAX) return NULL;
    return sk_X509_value(stack, (int)index);
}
void OB_x509_stack_free(STACK_OF(X509) *stack) {
    sk_X509_pop_free(stack, X509_free);
}
#if OB_BACKEND_CODE == 2 || OB_BACKEND_CODE == 3
#include <openssl/bytestring.h>
int OB_private_key_pkcs8(const EVP_PKEY *key, unsigned char *output, size_t capacity, size_t *length) {
    CBB bytes;
    *length = 0;
    if (!CBB_init_fixed(&bytes, output, capacity)) return 0;
    if (!EVP_marshal_private_key(&bytes, key) ||
        !CBB_finish(&bytes, NULL, length)) {
        /* Failed builders only permit cleanup. The Rust caller owns and
         * erases the entire fixed output buffer, including partial writes. */
        CBB_cleanup(&bytes);
        return 0;
    }
    return 1;
}
#endif
#if OB_BACKEND_CODE == 0 || OB_BACKEND_CODE == 1
int OB_pkcs7_kind(const PKCS7 *p7) {
    return p7->type == NULL ? -1 : OBJ_obj2nid(p7->type);
}
const STACK_OF(X509) *OB_pkcs7_certificates(const PKCS7 *p7) {
    if (OB_pkcs7_kind(p7) != NID_pkcs7_signed || p7->d.sign == NULL)
        return NULL;
    return p7->d.sign->cert;
}
#endif

/* Keep macro evaluation in the selected backend's C headers. */
int OB_md_size(const EVP_MD *md) { return EVP_MD_size(md); }
int OB_md_block_size(const EVP_MD *md) { return EVP_MD_block_size(md); }
int OB_md_is_xof(const EVP_MD *md) {
#ifdef EVP_MD_FLAG_XOF
    return (EVP_MD_flags(md) & EVP_MD_FLAG_XOF) != 0;
#else
    (void)md;
    return 0;
#endif
}
int OB_err_lib(unsigned long code) { return ERR_GET_LIB(code); }
int OB_err_reason(unsigned long code) { return ERR_GET_REASON(code); }
int OB_cipher_key_size(const EVP_CIPHER *cipher) { return EVP_CIPHER_key_length(cipher); }
int OB_cipher_iv_size(const EVP_CIPHER *cipher) {
#if OB_BACKEND_CODE == 3
    /* AWS-LC's legacy Blowfish ECB descriptor reports an eight-byte IV,
     * although ECB does not use one. Pass NULL to native initialization. */
    if (cipher == EVP_bf_ecb()) return 0;
#endif
    return EVP_CIPHER_iv_length(cipher);
}
int OB_cipher_block_size(const EVP_CIPHER *cipher) { return EVP_CIPHER_block_size(cipher); }
int OB_signature_md(EVP_PKEY_CTX *ctx, const EVP_MD *md) { return EVP_PKEY_CTX_set_signature_md(ctx, md); }
int OB_rsa_padding(EVP_PKEY_CTX *ctx, int padding) { return EVP_PKEY_CTX_set_rsa_padding(ctx, padding); }
int OB_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md) { return EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, md); }
int OB_rsa_oaep_md(EVP_PKEY_CTX *ctx, const EVP_MD *md) { return EVP_PKEY_CTX_set_rsa_oaep_md(ctx, md); }
int OB_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int length) { return EVP_PKEY_CTX_set_rsa_pss_saltlen(ctx, length); }
int OB_rsa_oaep_label(EVP_PKEY_CTX *ctx, const unsigned char *label, int length) {
    unsigned char *copy;
    int result;
    if (length < 0) return 0;
    /* LibreSSL does not retain a non-NULL allocation when length is zero. */
    if (length == 0) return EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, NULL, 0);
    /* The successful set0 call owns this exact OpenSSL allocation;
     * failure retains ownership. */
    copy = OPENSSL_malloc((size_t)length);
    if (copy == NULL) return 0;
    if (length != 0) memcpy(copy, label, (size_t)length);
    result = EVP_PKEY_CTX_set0_rsa_oaep_label(ctx, copy, length);
    if (result <= 0) OPENSSL_free(copy);
    return result;
}

int OB_signature_nonce(EVP_PKEY_CTX *ctx, unsigned int nonce_type) {
#if OB_BACKEND_CODE == 0 && OPENSSL_VERSION_NUMBER >= 0x30200000L
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_uint("nonce-type", &nonce_type);
    params[1] = OSSL_PARAM_construct_end();
    return EVP_PKEY_CTX_set_params(ctx, params);
#else
    (void)ctx;
    (void)nonce_type;
    return 0;
#endif
}

#if defined(OPENSSL_IS_BORINGSSL) && !defined(OPENSSL_IS_AWSLC)
void OB_CBS_init(CBS *cbs, const unsigned char *data, size_t length) {
    CBS_init(cbs, data, length);
}
#endif

void OB_bio_clear_retry(BIO *bio) { BIO_clear_retry_flags(bio); }
void OB_bio_retry_read(BIO *bio) { BIO_set_retry_read(bio); }
void OB_bio_retry_write(BIO *bio) { BIO_set_retry_write(bio); }

/* Normalize the control operations that differ between fork headers. */
int OB_dgram_control_kind(int command) {
    switch (command) {
    case BIO_CTRL_DGRAM_QUERY_MTU:
#ifdef BIO_CTRL_DGRAM_GET_MTU
    case BIO_CTRL_DGRAM_GET_MTU:
#endif
    case BIO_CTRL_DGRAM_GET_FALLBACK_MTU: return 1;
    case BIO_CTRL_DGRAM_SET_MTU: return 2;
#ifdef BIO_CTRL_DGRAM_SET_PEEK_MODE
    case BIO_CTRL_DGRAM_SET_PEEK_MODE: return 3;
#endif
#ifdef BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT
    case BIO_CTRL_DGRAM_SET_NEXT_TIMEOUT: return 4;
#endif
    /* No IP/UDP headers exist in this abstract ciphertext transport. */
#ifdef BIO_CTRL_DGRAM_GET_MTU_OVERHEAD
    case BIO_CTRL_DGRAM_GET_MTU_OVERHEAD: return 5;
#endif
    default: return 0;
    }
}
int OB_dtls_set_mtu(SSL *ssl, unsigned int mtu) {
    SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
    return SSL_set_mtu(ssl, mtu) > 0;
}
int OB_dtls_timeout(SSL *ssl, uint64_t *microseconds) {
    struct timeval timeout;
    if (!DTLSv1_get_timeout(ssl, &timeout)) return 0;
    if (timeout.tv_sec < 0 || timeout.tv_usec < 0 || timeout.tv_usec >= 1000000)
        return -1;
    *microseconds = (uint64_t)timeout.tv_sec * 1000000 + (uint64_t)timeout.tv_usec;
    return 1;
}
int OB_dtls_handle_timeout(SSL *ssl) { return DTLSv1_handle_timeout(ssl); }
int OB_dtls_listen(SSL *ssl, unsigned int mtu) {
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
    (void)ssl; (void)mtu; return -2;
#elif defined(LIBRESSL_VERSION_NUMBER)
    struct sockaddr_storage peer;
    memset(&peer, 0, sizeof(peer));
    /* SSL_clear can replace LibreSSL's DTLS state when the negotiated method
     * differs from the factory's method, losing its MTU. Restore it before the
     * internal clear in DTLSv1_listen, which then keeps the same method. */
    if (!SSL_clear(ssl) || !OB_dtls_set_mtu(ssl, mtu)) return -1;
    return DTLSv1_listen(ssl, (struct sockaddr *)&peer);
#else
    BIO_ADDR *peer = BIO_ADDR_new();
    int result;
    (void)mtu;
    if (peer == NULL) return -1;
    result = DTLSv1_listen(ssl, peer);
    BIO_ADDR_free(peer);
    return result;
#endif
}
size_t OB_dtls_data_mtu(SSL *ssl, unsigned int mtu) {
#if defined(OPENSSL_IS_BORINGSSL) || defined(OPENSSL_IS_AWSLC)
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    size_t overhead;
    if (cipher == NULL || !SSL_CIPHER_is_aead(cipher)) return 0;
    overhead = SSL_max_seal_overhead(ssl);
    return overhead >= mtu ? 0 : mtu - overhead;
#elif defined(LIBRESSL_VERSION_NUMBER)
    (void)ssl; (void)mtu; return 0;
#else
    (void)mtu;
    return DTLS_get_data_mtu(ssl);
#endif
}
