// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use crate::OpenSSLResult;

pub fn bn_to_big_endian_bytes(b: &openssl::bn::BigNumRef) -> OpenSSLResult<Vec<u8>> {
    b.to_vec_padded(b.num_bits() / 8 + 1)
}
