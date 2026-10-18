// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! SEC 1 / RFC 5915 EC private keys, as raw components.
//! TODO(verified-garbage): stub.

use cryptography_x509::common::EcParameters;

use crate::raw::EcPrivateKey;
use crate::{KeyParsingError, KeyParsingResult, KeySerializationResult};

/// Serializes `key`, whose `public_point` must be present (uncompressed).
pub fn serialize_pkcs1_private_key(
    key: &EcPrivateKey,
    include_curve: bool,
) -> KeySerializationResult<Vec<u8>> {
    let _ = (key, include_curve);
    unimplemented!("verified-garbage: EC private key serialization")
}

pub fn parse_pkcs1_private_key(
    data: &[u8],
    ec_params: Option<EcParameters<'_>>,
) -> KeyParsingResult<EcPrivateKey> {
    let _ = (data, ec_params);
    Err(KeyParsingError::InvalidKey)
}
