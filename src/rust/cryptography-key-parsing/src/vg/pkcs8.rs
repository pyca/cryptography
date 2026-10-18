// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! PKCS #8. TODO(verified-garbage): stub.

use crate::{KeyParsingError, KeyParsingResult, ParsedPrivateKey};

pub fn parse_private_key(data: &[u8]) -> KeyParsingResult<ParsedPrivateKey> {
    let _ = data;
    Err(KeyParsingError::InvalidKey)
}

pub fn parse_encrypted_private_key(
    data: &[u8],
    password: Option<&[u8]>,
) -> KeyParsingResult<ParsedPrivateKey> {
    let _ = (data, password);
    Err(KeyParsingError::InvalidKey)
}

/// Serializes `key`; an EC key's `public_point` must be present.
pub fn serialize_private_key(key: &ParsedPrivateKey) -> crate::KeySerializationResult<Vec<u8>> {
    let _ = key;
    unimplemented!("verified-garbage: PKCS #8 serialization")
}

pub fn serialize_encrypted_private_key(
    key: &ParsedPrivateKey,
    password: &[u8],
) -> crate::KeySerializationResult<Vec<u8>> {
    let _ = (key, password);
    unimplemented!("verified-garbage: encrypted PKCS #8 serialization")
}
