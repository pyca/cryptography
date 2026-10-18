// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! SubjectPublicKeyInfo. TODO(verified-garbage): stub.

use crate::raw::PublicKey;
use crate::{KeyParsingError, KeyParsingResult, KeySerializationResult, ParsedPublicKey};

pub fn parse_public_key(data: &[u8]) -> KeyParsingResult<ParsedPublicKey> {
    let _ = data;
    Err(KeyParsingError::InvalidKey)
}

pub fn serialize_public_key(key: &PublicKey) -> KeySerializationResult<Vec<u8>> {
    let _ = key;
    unimplemented!("verified-garbage: SPKI serialization")
}
