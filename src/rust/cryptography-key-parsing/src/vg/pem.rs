// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Legacy PEM encryption. TODO(verified-garbage): stub.

use std::borrow::Cow;

use crate::{KeyParsingError, KeyParsingResult};

pub fn decrypt_pem<'a>(
    pem: &'a pem::Pem,
    password: Option<&[u8]>,
) -> KeyParsingResult<(Cow<'a, [u8]>, bool)> {
    let _ = password;
    if pem.headers().get("Proc-Type").is_some() {
        return Err(KeyParsingError::PemUnsupportedCipher);
    }
    Ok((Cow::Borrowed(pem.contents()), false))
}

pub const ENCODE_CONFIG: pem::EncodeConfig =
    pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);

pub fn encrypt_pem(
    tag: &str,
    der_data: &[u8],
    password: &[u8],
) -> crate::KeySerializationResult<Vec<u8>> {
    let _ = (tag, der_data, password);
    unimplemented!("verified-garbage: PEM encryption")
}
