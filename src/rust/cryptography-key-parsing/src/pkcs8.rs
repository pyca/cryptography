// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use cryptography_x509::common::{AlgorithmIdentifier, AlgorithmParameters};
use cryptography_x509::csr::Attributes;

use crate::{ec, rsa, KeyParsingError, KeyParsingResult};

// RFC 5208 Section 5
#[derive(asn1::Asn1Read)]
struct PrivateKeyInfo<'a> {
    version: u8,
    algorithm: AlgorithmIdentifier<'a>,
    private_key: &'a [u8],
    #[implicit(0)]
    _attributes: Option<Attributes<'a>>,
}

pub fn parse_private_key(
    data: &[u8],
) -> KeyParsingResult<openssl::pkey::PKey<openssl::pkey::Private>> {
    let k = asn1::parse_single::<PrivateKeyInfo<'_>>(data)?;
    if k.version != 0 {
        return Err(crate::KeyParsingError::InvalidKey);
    }
    match k.algorithm.params {
        AlgorithmParameters::Rsa(_) | AlgorithmParameters::RsaPss(_) => {
            rsa::parse_pkcs1_private_key(k.private_key)
        }
        AlgorithmParameters::Ec(ec_params) => {
            ec::parse_pkcs1_private_key(k.private_key, Some(ec_params))
        }

        AlgorithmParameters::Dsa(dsa_params) => {
            let dsa_private_key = openssl::bn::BigNum::from_slice(
                asn1::parse_single::<asn1::BigUint<'_>>(k.private_key)?.as_bytes(),
            )?;
            let p = openssl::bn::BigNum::from_slice(dsa_params.p.as_bytes())?;
            let q = openssl::bn::BigNum::from_slice(dsa_params.q.as_bytes())?;
            let g = openssl::bn::BigNum::from_slice(dsa_params.g.as_bytes())?;

            let mut bn_ctx = openssl::bn::BigNumContext::new()?;
            let mut pub_key = openssl::bn::BigNum::new()?;
            pub_key.mod_exp(&g, &dsa_private_key, &p, &mut bn_ctx)?;

            let dsa =
                openssl::dsa::Dsa::from_private_components(p, q, g, dsa_private_key, pub_key)?;
            Ok(openssl::pkey::PKey::from_dsa(dsa)?)
        }

        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        AlgorithmParameters::Dh(dh_params) => {
            let dh_private_key = openssl::bn::BigNum::from_slice(
                asn1::parse_single::<asn1::BigUint<'_>>(k.private_key)?.as_bytes(),
            )?;
            let p = openssl::bn::BigNum::from_slice(dh_params.p.as_bytes())?;
            let g = openssl::bn::BigNum::from_slice(dh_params.g.as_bytes())?;
            let q = openssl::bn::BigNum::from_slice(dh_params.q.as_bytes())?;

            let dh = openssl::dh::Dh::from_params(p, g, q)?;
            let dh = dh.set_private_key(dh_private_key)?;
            Ok(openssl::pkey::PKey::from_dh(dh)?)
        }

        #[cfg(not(CRYPTOGRAPHY_IS_BORINGSSL))]
        AlgorithmParameters::DhKeyAgreement(dh_params) => {
            let dh_private_key = openssl::bn::BigNum::from_slice(
                asn1::parse_single::<asn1::BigUint<'_>>(k.private_key)?.as_bytes(),
            )?;
            let p = openssl::bn::BigNum::from_slice(dh_params.p.as_bytes())?;
            let g = openssl::bn::BigNum::from_slice(dh_params.g.as_bytes())?;

            let dh = openssl::dh::Dh::from_pqg(p, None, g)?;
            let dh = dh.set_private_key(dh_private_key)?;
            Ok(openssl::pkey::PKey::from_dh(dh)?)
        }

        AlgorithmParameters::X25519 => Ok(openssl::pkey::PKey::private_key_from_raw_bytes(
            asn1::parse_single(k.private_key)?,
            openssl::pkey::Id::X25519,
        )?),
        #[cfg(all(not(CRYPTOGRAPHY_IS_LIBRESSL), not(CRYPTOGRAPHY_IS_BORINGSSL)))]
        AlgorithmParameters::X448 => Ok(openssl::pkey::PKey::private_key_from_raw_bytes(
            asn1::parse_single(k.private_key)?,
            openssl::pkey::Id::X448,
        )?),
        AlgorithmParameters::Ed25519 => Ok(openssl::pkey::PKey::private_key_from_raw_bytes(
            asn1::parse_single(k.private_key)?,
            openssl::pkey::Id::ED25519,
        )?),
        #[cfg(all(not(CRYPTOGRAPHY_IS_LIBRESSL), not(CRYPTOGRAPHY_IS_BORINGSSL)))]
        AlgorithmParameters::Ed448 => Ok(openssl::pkey::PKey::private_key_from_raw_bytes(
            asn1::parse_single(k.private_key)?,
            openssl::pkey::Id::ED448,
        )?),

        _ => Err(KeyParsingError::UnsupportedKeyType(
            k.algorithm.oid().clone(),
        )),
    }
}
