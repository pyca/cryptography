// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

lazy_static::lazy_static! {
    pub(crate) static ref EXTENSION_REQUEST: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.9.14").unwrap();
    pub(crate) static ref MS_EXTENSION_REQUEST: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.311.2.1.14").unwrap();
    pub(crate) static ref PRECERT_SIGNED_CERTIFICATE_TIMESTAMPS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.11129.2.4.2").unwrap();
    pub(crate) static ref PRECERT_POISON_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.11129.2.4.3").unwrap();
    pub(crate) static ref SIGNED_CERTIFICATE_TIMESTAMPS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.4.1.11129.2.4.5").unwrap();
    pub(crate) static ref AUTHORITY_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.1").unwrap();
    pub(crate) static ref SUBJECT_INFORMATION_ACCESS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.11").unwrap();
    pub(crate) static ref TLS_FEATURE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.1.24").unwrap();
    pub(crate) static ref CP_CPS_URI_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.2.1").unwrap();
    pub(crate) static ref CP_USER_NOTICE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.2.2").unwrap();
    pub(crate) static ref NONCE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.2").unwrap();
    pub(crate) static ref OCSP_NO_CHECK_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.6.1.5.5.7.48.1.5").unwrap();
    pub(crate) static ref SUBJECT_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.14").unwrap();
    pub(crate) static ref KEY_USAGE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.15").unwrap();
    pub(crate) static ref SUBJECT_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.17").unwrap();
    pub(crate) static ref ISSUER_ALTERNATIVE_NAME_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.18").unwrap();
    pub(crate) static ref BASIC_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.19").unwrap();
    pub(crate) static ref CRL_NUMBER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.20").unwrap();
    pub(crate) static ref CRL_REASON_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.21").unwrap();
    pub(crate) static ref INVALIDITY_DATE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.24").unwrap();
    pub(crate) static ref DELTA_CRL_INDICATOR_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.27").unwrap();
    pub(crate) static ref ISSUING_DISTRIBUTION_POINT_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.28").unwrap();
    pub(crate) static ref CERTIFICATE_ISSUER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.29").unwrap();
    pub(crate) static ref NAME_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.30").unwrap();
    pub(crate) static ref CRL_DISTRIBUTION_POINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.31").unwrap();
    pub(crate) static ref CERTIFICATE_POLICIES_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.32").unwrap();
    pub(crate) static ref AUTHORITY_KEY_IDENTIFIER_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.35").unwrap();
    pub(crate) static ref POLICY_CONSTRAINTS_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.36").unwrap();
    pub(crate) static ref EXTENDED_KEY_USAGE_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.37").unwrap();
    pub(crate) static ref FRESHEST_CRL_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.46").unwrap();
    pub(crate) static ref INHIBIT_ANY_POLICY_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.5.29.54").unwrap();

    // Signing methods
    pub(crate) static ref ECDSA_WITH_SHA1_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.1").unwrap();
    pub(crate) static ref ECDSA_WITH_SHA224_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.3.1").unwrap();
    pub(crate) static ref ECDSA_WITH_SHA256_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.3.2").unwrap();
    pub(crate) static ref ECDSA_WITH_SHA384_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.3.3").unwrap();
    pub(crate) static ref ECDSA_WITH_SHA512_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.10045.4.3.4").unwrap();

    pub(crate) static ref RSA_WITH_MD5_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.4").unwrap();
    pub(crate) static ref RSA_WITH_SHA1_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.5").unwrap();
    pub(crate) static ref RSA_WITH_SHA224_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.14").unwrap();
    pub(crate) static ref RSA_WITH_SHA256_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.11").unwrap();
    pub(crate) static ref RSA_WITH_SHA384_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.12").unwrap();
    pub(crate) static ref RSA_WITH_SHA512_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.113549.1.1.13").unwrap();

    pub(crate) static ref DSA_WITH_SHA1_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.2.840.10040.4.3").unwrap();
    pub(crate) static ref DSA_WITH_SHA224_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.3.1").unwrap();
    pub(crate) static ref DSA_WITH_SHA256_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.3.2").unwrap();
    pub(crate) static ref DSA_WITH_SHA384_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.3.3").unwrap();
    pub(crate) static ref DSA_WITH_SHA512_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.3.4").unwrap();

    pub(crate) static ref ED25519_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.101.112").unwrap();
    pub(crate) static ref ED448_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.101.113").unwrap();

    // Hashes
    pub(crate) static ref SHA1_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("1.3.14.3.2.26").unwrap();
    pub(crate) static ref SHA224_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.4").unwrap();
    pub(crate) static ref SHA256_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.1").unwrap();
    pub(crate) static ref SHA384_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.2").unwrap();
    pub(crate) static ref SHA512_OID: asn1::ObjectIdentifier<'static> = asn1::ObjectIdentifier::from_string("2.16.840.1.101.3.4.2.3").unwrap();
}
