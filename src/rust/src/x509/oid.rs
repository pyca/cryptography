// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

pub(crate) const EXTENSION_REQUEST: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 9, 14);
pub(crate) const MS_EXTENSION_REQUEST: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 311, 2, 1, 14);
pub(crate) const MS_CERTIFICATE_TEMPLATE: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 311, 21, 7);
pub(crate) const PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 11129, 2, 4, 2);
pub(crate) const PRECERT_POISON_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 11129, 2, 4, 3);
pub(crate) const SIGNED_CERTIFICATE_TIMESTAMPS_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 4, 1, 11129, 2, 4, 5);
pub(crate) const AUTHORITY_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 5, 5, 7, 1, 1);
pub(crate) const SUBJECT_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 5, 5, 7, 1, 11);
pub(crate) const TLS_FEATURE_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 1, 24);
pub(crate) const CP_CPS_URI_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 2, 1);
pub(crate) const CP_USER_NOTICE_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 2, 2);
pub(crate) const NONCE_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 6, 1, 5, 5, 7, 48, 1, 2);
pub(crate) const OCSP_NO_CHECK_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 5, 5, 7, 48, 1, 5);
pub(crate) const SUBJECT_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 14);
pub(crate) const KEY_USAGE_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 15);
pub(crate) const SUBJECT_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 17);
pub(crate) const ISSUER_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 18);
pub(crate) const BASIC_CONSTRAINTS_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 19);
pub(crate) const CRL_NUMBER_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 20);
pub(crate) const CRL_REASON_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 21);
pub(crate) const INVALIDITY_DATE_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 24);
pub(crate) const DELTA_CRL_INDICATOR_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 27);
pub(crate) const ISSUING_DISTRIBUTION_POINT_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 28);
pub(crate) const CERTIFICATE_ISSUER_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 29);
pub(crate) const NAME_CONSTRAINTS_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 30);
pub(crate) const CRL_DISTRIBUTION_POINTS_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 31);
pub(crate) const CERTIFICATE_POLICIES_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 32);
pub(crate) const AUTHORITY_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 35);
pub(crate) const POLICY_CONSTRAINTS_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 36);
pub(crate) const EXTENDED_KEY_USAGE_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 37);
pub(crate) const FRESHEST_CRL_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 46);
pub(crate) const INHIBIT_ANY_POLICY_OID: asn1::ObjectIdentifier = asn1::oid!(2, 5, 29, 54);
pub(crate) const ACCEPTABLE_RESPONSES_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 3, 6, 1, 5, 5, 7, 48, 1, 4);

// Signing methods
pub(crate) const ECDSA_WITH_SHA224_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 10045, 4, 3, 1);
pub(crate) const ECDSA_WITH_SHA256_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 10045, 4, 3, 2);
pub(crate) const ECDSA_WITH_SHA384_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 10045, 4, 3, 3);
pub(crate) const ECDSA_WITH_SHA512_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 10045, 4, 3, 4);
pub(crate) const ECDSA_WITH_SHA3_224_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 9);
pub(crate) const ECDSA_WITH_SHA3_256_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 10);
pub(crate) const ECDSA_WITH_SHA3_384_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 11);
pub(crate) const ECDSA_WITH_SHA3_512_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 12);

pub(crate) const RSA_WITH_SHA224_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 14);
pub(crate) const RSA_WITH_SHA256_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 11);
pub(crate) const RSA_WITH_SHA384_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 12);
pub(crate) const RSA_WITH_SHA512_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 1, 13);
pub(crate) const RSA_WITH_SHA3_224_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 13);
pub(crate) const RSA_WITH_SHA3_256_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 14);
pub(crate) const RSA_WITH_SHA3_384_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 15);
pub(crate) const RSA_WITH_SHA3_512_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 16);

pub(crate) const DSA_WITH_SHA224_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 1);
pub(crate) const DSA_WITH_SHA256_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 2);
pub(crate) const DSA_WITH_SHA384_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 3);
pub(crate) const DSA_WITH_SHA512_OID: asn1::ObjectIdentifier =
    asn1::oid!(2, 16, 840, 1, 101, 3, 4, 3, 4);

pub(crate) const ED25519_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 101, 112);
pub(crate) const ED448_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 101, 113);

// Hashes
pub(crate) const SHA1_OID: asn1::ObjectIdentifier = asn1::oid!(1, 3, 14, 3, 2, 26);
pub(crate) const SHA224_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 4);
pub(crate) const SHA256_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 1);
pub(crate) const SHA384_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 2);
pub(crate) const SHA512_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 3);
