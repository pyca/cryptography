# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

from __future__ import absolute_import, division, print_function

# This is a mapping of {condition: names-dependent-on-that-condition} so we can
# loop over them and delete unsupported names at runtime. It will be removed
# when cffi supports #if in cdef.

CONDITIONAL_NAMES = {
    "Cryptography_HAS_CMS": [
        "BIO_new_CMS",
        "i2d_CMS_bio_stream",
        "PEM_write_bio_CMS_stream",
        "CMS_final",
        "CMS_sign",
        "CMS_verify",
        "CMS_encrypt",
        "CMS_decrypt",
        "CMS_add1_signer",
        "CMS_TEXT",
        "CMS_NOCERTS",
        "CMS_NO_CONTENT_VERIFY",
        "CMS_NO_ATTR_VERIFY",
        "CMS_NOSIGS",
        "CMS_NOINTERN",
        "CMS_NO_SIGNER_CERT_VERIFY",
        "CMS_NOVERIFY",
        "CMS_DETACHED",
        "CMS_BINARY",
        "CMS_NOATTR",
        "CMS_NOSMIMECAP",
        "CMS_NOOLDMIMETYPE",
        "CMS_CRLFEOL",
        "CMS_STREAM",
        "CMS_NOCRL",
        "CMS_PARTIAL",
        "CMS_REUSE_DIGEST",
        "CMS_USE_KEYID",
        "CMS_DEBUG_DECRYPT",
    ],

    "Cryptography_HAS_EC2M": [
        "EC_GF2m_simple_method",
        "EC_POINT_set_affine_coordinates_GF2m",
        "EC_POINT_get_affine_coordinates_GF2m",
        "EC_POINT_set_compressed_coordinates_GF2m",
        "EC_GROUP_set_curve_GF2m",
        "EC_GROUP_get_curve_GF2m",
        "EC_GROUP_new_curve_GF2m",
    ],

    "Cryptography_HAS_EC_1_0_2": [
        "EC_curve_nid2nist",
    ],
    "Cryptography_HAS_SET_ECDH_AUTO": [
        "SSL_CTX_set_ecdh_auto",
    ],
    "Cryptography_HAS_ENGINE_CRYPTODEV": [
        "ENGINE_load_cryptodev"
    ],
    "Cryptography_HAS_RSA_R_PKCS_DECODING_ERROR": [
        "RSA_R_PKCS_DECODING_ERROR"
    ],
    "Cryptography_HAS_EGD": [
        "RAND_egd",
        "RAND_egd_bytes",
        "RAND_query_egd_bytes",
    ],
    "Cryptography_HAS_RSA_OAEP_MD": [
        "EVP_PKEY_CTX_set_rsa_oaep_md",
    ],

    "Cryptography_HAS_SSL3_METHOD": [
        "SSLv3_method",
        "SSLv3_client_method",
        "SSLv3_server_method",
    ],

    "Cryptography_HAS_ALPN": [
        "SSL_CTX_set_alpn_protos",
        "SSL_set_alpn_protos",
        "SSL_CTX_set_alpn_select_cb",
        "SSL_get0_alpn_selected",
    ],

    "Cryptography_HAS_COMPRESSION": [
        "SSL_get_current_compression",
        "SSL_get_current_expansion",
        "SSL_COMP_get_name",
    ],

    "Cryptography_HAS_GET_SERVER_TMP_KEY": [
        "SSL_get_server_tmp_key",
    ],

    "Cryptography_HAS_102_VERIFICATION_ERROR_CODES": [
        'X509_V_ERR_SUITE_B_INVALID_VERSION',
        'X509_V_ERR_SUITE_B_INVALID_ALGORITHM',
        'X509_V_ERR_SUITE_B_INVALID_CURVE',
        'X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM',
        'X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED',
        'X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256',
        'X509_V_ERR_HOSTNAME_MISMATCH',
        'X509_V_ERR_EMAIL_MISMATCH',
        'X509_V_ERR_IP_ADDRESS_MISMATCH'
    ],
    "Cryptography_HAS_102_VERIFICATION_PARAMS": [
        "X509_V_FLAG_SUITEB_128_LOS_ONLY",
        "X509_V_FLAG_SUITEB_192_LOS",
        "X509_V_FLAG_SUITEB_128_LOS",
        "X509_VERIFY_PARAM_set1_host",
        "X509_VERIFY_PARAM_set1_email",
        "X509_VERIFY_PARAM_set1_ip",
        "X509_VERIFY_PARAM_set1_ip_asc",
        "X509_VERIFY_PARAM_set_hostflags",
    ],
    "Cryptography_HAS_X509_V_FLAG_TRUSTED_FIRST": [
        "X509_V_FLAG_TRUSTED_FIRST",
    ],
    "Cryptography_HAS_X509_V_FLAG_PARTIAL_CHAIN": [
        "X509_V_FLAG_PARTIAL_CHAIN",
    ],
    "Cryptography_HAS_SET_CERT_CB": [
        "SSL_CTX_set_cert_cb",
        "SSL_set_cert_cb",
    ],
    "Cryptography_HAS_SSL_ST": [
        "SSL_ST_BEFORE",
        "SSL_ST_OK",
        "SSL_ST_INIT",
        "SSL_ST_RENEGOTIATE",
    ],
    "Cryptography_HAS_TLS_ST": [
        "TLS_ST_BEFORE",
        "TLS_ST_OK",
    ],
    "Cryptography_HAS_LOCKING_CALLBACKS": [
        "CRYPTO_LOCK",
        "CRYPTO_UNLOCK",
        "CRYPTO_READ",
        "CRYPTO_LOCK_SSL",
        "CRYPTO_lock",
    ],
    "Cryptography_HAS_SCRYPT": [
        "EVP_PBE_scrypt",
    ],
    "Cryptography_HAS_DTLS": [
        "Cryptography_DTLSv1_get_timeout",
        "DTLSv1_handle_timeout",
    ],
    "Cryptography_HAS_EVP_PKEY_DHX": [
        "EVP_PKEY_DHX",
        "Cryptography_d2i_DHxparams_bio",
        "Cryptography_i2d_DHxparams_bio",
        "PEM_write_bio_DHxparams",
    ],
    "Cryptography_HAS_MEM_FUNCTIONS": [
        "Cryptography_CRYPTO_set_mem_functions",
    ],
    "Cryptography_HAS_SCT": [
        "SCT_get_version",
        "SCT_get_log_entry_type",
        "SCT_get0_log_id",
        "SCT_get_timestamp",
        "SCT_set_source",
        "sk_SCT_num",
        "sk_SCT_value",
        "SCT_LIST_free",
    ],
    "Cryptography_HAS_X509_STORE_CTX_GET_ISSUER": [
        "X509_STORE_get_get_issuer",
        "X509_STORE_set_get_issuer",
    ],
    "Cryptography_HAS_X25519": [
        "NID_X25519",
    ],
}
