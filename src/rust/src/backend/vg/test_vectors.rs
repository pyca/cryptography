// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Reading the known-answer test vectors of `vectors/cryptography_vectors/`
//! in the unit tests of the verified-garbage modules.

use std::collections::HashMap;

/// The contents of `vectors/cryptography_vectors/<path>`.
pub(crate) fn read(path: &str) -> String {
    let full = format!(
        "{}/../../vectors/cryptography_vectors/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("reading {full}: {e}"))
}

/// Hex-decodes `v` (empty for an empty string).
pub(crate) fn unhex(v: &str) -> Vec<u8> {
    cryptography_crypto::encoding::hex_decode(v).expect("valid hex")
}

/// The vectors of a NIST-style file: blocks of `KEY = value` lines separated
/// by blank lines or starting at `COUNT` (keys lowercased; `#` comments and `[...]` sections
/// skipped), as `tests/utils.py`'s `load_nist_vectors` reads them. At most
/// `limit` vectors are returned.
pub(crate) fn load_nist_vectors(data: &str, limit: usize) -> Vec<HashMap<String, String>> {
    let mut vectors = vec![];
    let mut current = HashMap::new();
    for line in data.lines() {
        let line = line.trim();
        if line.starts_with('#') || line.starts_with('[') {
            continue;
        }
        if line.is_empty() {
            if !current.is_empty() {
                vectors.push(std::mem::take(&mut current));
                if vectors.len() == limit {
                    return vectors;
                }
            }
            continue;
        }
        let (key, value) = line.split_once('=').expect("a KEY = value line");
        let key = key.trim().to_lowercase();
        // A `COUNT` line starts a vector even without a blank line before it.
        if key == "count" && !current.is_empty() {
            vectors.push(std::mem::take(&mut current));
            if vectors.len() == limit {
                return vectors;
            }
        }
        current.insert(key, value.trim().to_string());
    }
    if !current.is_empty() && vectors.len() < limit {
        vectors.push(current);
    }
    vectors
}

/// `unwrap` for the results of the Python-facing functions, whose errors
/// (`CryptographyError`) do not implement `Debug`: panics with the Python
/// exception.
pub(crate) trait Check<T> {
    fn check(self) -> T;
}

impl<T, E: Into<crate::error::CryptographyError>> Check<T> for Result<T, E> {
    fn check(self) -> T {
        match self {
            Ok(v) => v,
            Err(e) => panic!("{:?}", pyo3::PyErr::from(e.into())),
        }
    }
}
