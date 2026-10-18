// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! OpenSSL's traditional DSA private key format, as raw components.
//! TODO(verified-garbage): stub.

use crate::raw::DsaPrivateKey;
use crate::{KeyParsingError, KeyParsingResult, KeySerializationResult};

/// Serializes `key`, whose `y` must be present (the format includes it).
pub fn serialize_pkcs1_private_key(key: &DsaPrivateKey) -> KeySerializationResult<Vec<u8>> {
    let _ = key;
    unimplemented!("verified-garbage: DSA private key serialization")
}

/// Parses a key, with its `y`, which the backend must check is `g^x mod p`.
pub fn parse_pkcs1_private_key(data: &[u8]) -> KeyParsingResult<DsaPrivateKey> {
    let _ = data;
    Err(KeyParsingError::InvalidKey)
}
