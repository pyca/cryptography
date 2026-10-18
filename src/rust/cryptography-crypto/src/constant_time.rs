// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

/// Performs a constant-time comparison of two byte slices.
pub fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    #[cfg(feature = "openssl")]
    {
        openssl::memcmp::eq(a, b)
    }
    #[cfg(not(feature = "openssl"))]
    {
        // Accumulate the differences of every byte, so the time taken does
        // not depend on where (or whether) the slices differ; `black_box`
        // keeps the compiler from short-circuiting the loop.
        let mut diff = 0u8;
        for (x, y) in a.iter().zip(b) {
            diff |= std::hint::black_box(x ^ y);
        }
        std::hint::black_box(diff) == 0
    }
}
