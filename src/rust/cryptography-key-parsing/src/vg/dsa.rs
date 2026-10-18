// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! OpenSSL's traditional DSA private key format, as raw components.
//! TODO(verified-garbage): stub.

use crate::raw::DsaPrivateKey;
use crate::{KeyParsingError, KeyParsingResult, KeySerializationResult};

/// Serializes `key`, with its public value `y` (which the format includes).
pub fn serialize_pkcs1_private_key(
    key: &DsaPrivateKey,
    y: &[u8],
) -> KeySerializationResult<Vec<u8>> {
    let _ = (key, y);
    unimplemented!("verified-garbage: DSA private key serialization")
}

/// Parses a key; the backend checks that its `y` (dropped) is `g^x mod p`
/// by recomputing it.
pub fn parse_pkcs1_private_key(data: &[u8]) -> KeyParsingResult<DsaPrivateKey> {
    let _ = data;
    Err(KeyParsingError::InvalidKey)
}
