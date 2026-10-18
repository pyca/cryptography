// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! PKCS #1 RSA keys, as raw components. TODO(verified-garbage): stub.

use crate::raw::{RsaPrivateKey, RsaPublicKey};
use crate::{KeyParsingError, KeyParsingResult, KeySerializationResult};

pub fn parse_pkcs1_public_key(data: &[u8]) -> KeyParsingResult<RsaPublicKey> {
    let _ = data;
    Err(KeyParsingError::InvalidKey)
}

pub fn serialize_pkcs1_public_key(key: &RsaPublicKey) -> KeySerializationResult<Vec<u8>> {
    let _ = key;
    unimplemented!("verified-garbage: RSA public key serialization")
}

pub fn serialize_pkcs1_private_key(key: &RsaPrivateKey) -> KeySerializationResult<Vec<u8>> {
    let _ = key;
    unimplemented!("verified-garbage: RSA private key serialization")
}

pub fn parse_pkcs1_private_key(data: &[u8]) -> KeyParsingResult<RsaPrivateKey> {
    let _ = data;
    Err(KeyParsingError::InvalidKey)
}
