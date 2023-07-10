// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

// X.509v3 extensions
pub const EXTENSION_REQUEST: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 9, 14);
pub const MS_EXTENSION_REQUEST: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 311, 2, 1, 14);
pub const MS_CERTIFICATE_TEMPLATE: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 311, 21, 7);
pub const PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 11129, 2, 4, 2);
pub const PRECERT_POISON_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 4, 1, 11129, 2, 4, 3);
pub const SIGNED_CERTIFICATE_TIMESTAMPS_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 11129, 2, 4, 5);
pub const AUTHORITY_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 5, 5, 7, 1, 1);
pub const SUBJECT_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 5, 5, 7, 1, 11);
pub const TLS_FEATURE_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 1, 24);
pub const CP_CPS_URI_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 2, 1);
pub const CP_USER_NOTICE_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 2, 2);
pub const NONCE_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 48, 1, 2);
pub const OCSP_NO_CHECK_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 48, 1, 5);
pub const SUBJECT_DIRECTORY_ATTRIBUTES_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 9);
pub const SUBJECT_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 14);
pub const KEY_USAGE_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 15);
pub const SUBJECT_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 17);
pub const ISSUER_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 18);
pub const BASIC_CONSTRAINTS_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 19);
pub const CRL_NUMBER_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 20);
pub const CRL_REASON_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 21);
pub const INVALIDITY_DATE_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 24);
pub const DELTA_CRL_INDICATOR_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 27);
pub const ISSUING_DISTRIBUTION_POINT_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 28);
pub const CERTIFICATE_ISSUER_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 29);
pub const NAME_CONSTRAINTS_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 30);
pub const CRL_DISTRIBUTION_POINTS_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 31);
pub const CERTIFICATE_POLICIES_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 32);
pub const AUTHORITY_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 35);
pub const POLICY_CONSTRAINTS_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 36);
pub const EXTENDED_KEY_USAGE_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 37);
pub const FRESHEST_CRL_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 46);
pub const INHIBIT_ANY_POLICY_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 54);
pub const ACCEPTABLE_RESPONSES_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 5, 5, 7, 48, 1, 4);

// Signing methods
pub const ECDSA_WITH_SHA224_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 10045, 4, 3, 1);
pub const ECDSA_WITH_SHA256_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 10045, 4, 3, 2);
pub const ECDSA_WITH_SHA384_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 10045, 4, 3, 3);
pub const ECDSA_WITH_SHA512_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 10045, 4, 3, 4);
pub const ECDSA_WITH_SHA3_224_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 9);
pub const ECDSA_WITH_SHA3_256_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 10);
pub const ECDSA_WITH_SHA3_384_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 11);
pub const ECDSA_WITH_SHA3_512_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 12);

pub const RSA_WITH_SHA1_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 1, 5);
pub const RSA_WITH_SHA1_ALT_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 14, 3, 2, 29);
pub const RSA_WITH_SHA224_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 1, 14);
pub const RSA_WITH_SHA256_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 1, 11);
pub const RSA_WITH_SHA384_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 1, 12);
pub const RSA_WITH_SHA512_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 1, 13);
pub const RSA_WITH_SHA3_224_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 13);
pub const RSA_WITH_SHA3_256_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 14);
pub const RSA_WITH_SHA3_384_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 15);
pub const RSA_WITH_SHA3_512_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 16);

pub const DSA_WITH_SHA224_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 1);
pub const DSA_WITH_SHA256_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 2);
pub const DSA_WITH_SHA384_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 3);
pub const DSA_WITH_SHA512_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 4);

pub const ED25519_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 101, 112);
pub const ED448_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 101, 113);

// Hashes
pub const SHA1_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 14, 3, 2, 26);
pub const SHA224_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 4);
pub const SHA256_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 1);
pub const SHA384_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2);
pub const SHA512_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 3);
pub const SHA3_224_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 37476, 3, 2, 1, 99, 7, 224);
pub const SHA3_256_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 37476, 3, 2, 1, 99, 7, 256);
pub const SHA3_384_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 37476, 3, 2, 1, 99, 7, 384);
pub const SHA3_512_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 37476, 3, 2, 1, 99, 7, 512);

pub const MGF1_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 1, 8);
pub const RSASSA_PSS_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 1, 1, 10);

// Extended key usages
pub const EKU_SERVER_AUTH_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 3, 1);
pub const EKU_CLIENT_AUTH_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 3, 2);
pub const EKU_CODE_SIGNING_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 3, 3);
pub const EKU_EMAIL_PROTECTION_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 3, 4);
pub const EKU_TIME_STAMPING_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 3, 8);
pub const EKU_OCSP_SIGNING_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 3, 9);
pub const EKU_ANY_KEY_USAGE_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 37, 0);
pub const EKU_CERTIFICATE_TRANSPARENCY_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 11129, 2, 4, 4);
