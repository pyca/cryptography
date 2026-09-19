// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

/// Minimal positive DER INTEGER contents, including the required sign octet.
pub fn integer_bytes(bytes: &[u8]) -> openssl_bridge::secret::SecretBytes {
    let bytes = &bytes[bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len())..];
    let mut out = Vec::with_capacity(bytes.len() + 1);
    if bytes.first().is_none_or(|b| b & 0x80 != 0) {
        out.push(0);
    }
    out.extend_from_slice(bytes);
    out.into()
}
