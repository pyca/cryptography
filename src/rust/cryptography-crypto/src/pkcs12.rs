// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

pub const KDF_ENCRYPTION_KEY_ID: u8 = 1;
pub const KDF_IV_ID: u8 = 2;
pub const KDF_MAC_KEY_ID: u8 = 3;

pub fn kdf(
    pass: &str,
    salt: &[u8],
    id: u8,
    rounds: u64,
    key_len: usize,
    hash_alg: openssl::hash::MessageDigest,
) -> Result<Vec<u8>, openssl::error::ErrorStack> {
    // Encode the password as big-endian UTF-16 with NUL trailer
    let pass = pass
        .encode_utf16()
        .chain([0])
        .flat_map(|v| v.to_be_bytes())
        .collect::<Vec<u8>>();

    // Comments are borrowed from BoringSSL.
    // In the spec, |block_size| is called "v", but measured in bits.
    let block_size = hash_alg.block_size();

    // 1. Construct a string, D (the "diversifier"), by concatenating v/8 copies
    // of ID.
    let d = vec![id; block_size];

    // 2. Concatenate copies of the salt together to create a string S of length
    // v(ceiling(s/v)) bits (the final copy of the salt may be truncated to
    // create S). Note that if the salt is the empty string, then so is S.
    //
    // 3. Concatenate copies of the password together to create a string P of
    // length v(ceiling(p/v)) bits (the final copy of the password may be
    // truncated to create P).  Note that if the password is the empty string,
    // then so is P.
    //
    // 4. Set I=S||P to be the concatenation of S and P.
    let s_len = block_size * salt.len().div_ceil(block_size);
    let p_len = block_size * pass.len().div_ceil(block_size);

    let mut init_key = vec![0; s_len + p_len];
    for i in 0..s_len {
        init_key[i] = salt[i % salt.len()];
    }
    for i in 0..p_len {
        init_key[i + s_len] = pass[i % pass.len()];
    }

    let mut result = vec![0; key_len];
    let mut pos = 0;
    loop {
        // A. Set A_i=H^r(D||I). (i.e., the r-th hash of D||I,
        // H(H(H(... H(D||I))))

        let mut h = openssl::hash::Hasher::new(hash_alg)?;
        h.update(&d)?;
        h.update(&init_key)?;
        let mut a = h.finish()?;

        for _ in 1..rounds {
            let mut h = openssl::hash::Hasher::new(hash_alg)?;
            h.update(&a)?;
            a = h.finish()?;
        }

        let to_add = a.len().min(result.len() - pos);
        result[pos..pos + to_add].copy_from_slice(&a[..to_add]);
        pos += to_add;
        if pos == result.len() {
            break;
        }

        // B. Concatenate copies of A_i to create a string B of length v bits (the
        // final copy of A_i may be truncated to create B).
        let mut b = vec![0; block_size];
        for i in 0..block_size {
            b[i] = a[i % a.len()];
        }

        // C. Treating I as a concatenation I_0, I_1, ..., I_(k-1) of v-bit blocks,
        // where k=ceiling(s/v)+ceiling(p/v), modify I by setting I_j=(I_j+B+1) mod
        // 2^v for each j.
        assert!(init_key.len() % block_size == 0);
        let mut j = 0;
        while j < init_key.len() {
            let mut carry = 1u16;
            let mut k = block_size - 1;
            loop {
                carry += init_key[k + j] as u16 + b[k] as u16;
                init_key[j + k] = carry as u8;
                carry >>= 8;
                if k == 0 {
                    break;
                }
                k -= 1;
            }
            j += block_size;
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::{kdf, KDF_ENCRYPTION_KEY_ID, KDF_IV_ID, KDF_MAC_KEY_ID};

    #[test]
    fn test_pkcs12_kdf() {
        for (password, salt, id, rounds, key_len, hash, expected_key) in [
            // From https://github.com/RustCrypto/formats/blob/master/pkcs12/tests/kdf.rs
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 100, 32, openssl::hash::MessageDigest::sha256(), b"\xfa\xe4\xd4\x95z<\xc7\x81\xe1\x18\x0b\x9dO\xb7\x9c\x1e\x0c\x85y\xb7F\xa3\x17~[\x07h\xa3\x11\x8b\xf8c" as &[u8]),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_IV_ID, 100, 32, openssl::hash::MessageDigest::sha256(), b"\xe5\xff\x81;\xc6T}\xe5\x15[\x14\xd2\xfa\xda\x85\xb3 \x1a\x97sI\xdbn&\xcc\xc9\x98\xd9\xe8\xf8=l"),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_MAC_KEY_ID, 100, 32, openssl::hash::MessageDigest::sha256(), b"\x13cU\xed\x944Qf\x82SOF\xd69V\xdb_\xf0k\x84G\x02\xc2\xc1\xf3\xb4c!\xe2RJM"),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 100, 20, openssl::hash::MessageDigest::sha256(), b"\xfa\xe4\xd4\x95z<\xc7\x81\xe1\x18\x0b\x9dO\xb7\x9c\x1e\x0c\x85y\xb7"),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_IV_ID, 100, 20, openssl::hash::MessageDigest::sha256(), b"\xe5\xff\x81;\xc6T}\xe5\x15[\x14\xd2\xfa\xda\x85\xb3 \x1a\x97s"),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_MAC_KEY_ID, 100, 20, openssl::hash::MessageDigest::sha256(), b"\x13cU\xed\x944Qf\x82SOF\xd69V\xdb_\xf0k\x84"),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 100, 12, openssl::hash::MessageDigest::sha256(), b"\xfa\xe4\xd4\x95z<\xc7\x81\xe1\x18\x0b\x9d"),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_IV_ID, 100, 12, openssl::hash::MessageDigest::sha256(), b"\xe5\xff\x81;\xc6T}\xe5\x15[\x14\xd2"),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_MAC_KEY_ID, 100, 12, openssl::hash::MessageDigest::sha256(), b"\x13cU\xed\x944Qf\x82SOF"),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 1000, 32, openssl::hash::MessageDigest::sha256(), b"+\x95\xa0V\x9bc\xf6A\xfa\xe1\xef\xca2\xe8M\xb3i\x9a\xb7E@b\x8b\xa6b\x83\xb5\x8c\xf5@\x05'"),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_IV_ID, 1000, 32, openssl::hash::MessageDigest::sha256(), b"dr\xc0\xeb\xad?\xabA#\xe8\xb5\xedx4\xde!\xee\xb2\x01\x87\xb3\xef\xf7\x8a}\x1c\xdf\xfa@4\x85\x1d"),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_MAC_KEY_ID, 1000, 32, openssl::hash::MessageDigest::sha256(), b"?\x91\x13\xf0\\0\xa9\x96\xc4\xa5\x16@\x9b\xda\xc9\xd0e\xf4B\x96\xcc\xd5+\xb7]\xe3\xfc\xfd\xbe+\xf10"),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 1000, 100, openssl::hash::MessageDigest::sha256(), b"+\x95\xa0V\x9bc\xf6A\xfa\xe1\xef\xca2\xe8M\xb3i\x9a\xb7E@b\x8b\xa6b\x83\xb5\x8c\xf5@\x05\'\xd8\xd0\xeb\xe2\xcc\xbfv\x8cQ\xc4\xd8\xfb\xd1\xbb\x15k\xe0l\x1cY\xcb\xb6\x9eD\x05/\xfc77o\xdbG\xb2\xde\x7f\x9eT=\xe9\xd0\x96\xd8\xe5GK\"\x04\x10\xff\x1c]\x8b\xb7\xe5\xbc\x0fa\xba\xea\xa1/\xd0\xda\x1dz\x97\x01r"),
            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 1000, 200, openssl::hash::MessageDigest::sha256(), b"+\x95\xa0V\x9bc\xf6A\xfa\xe1\xef\xca2\xe8M\xb3i\x9a\xb7E@b\x8b\xa6b\x83\xb5\x8c\xf5@\x05\'\xd8\xd0\xeb\xe2\xcc\xbfv\x8cQ\xc4\xd8\xfb\xd1\xbb\x15k\xe0l\x1cY\xcb\xb6\x9eD\x05/\xfc77o\xdbG\xb2\xde\x7f\x9eT=\xe9\xd0\x96\xd8\xe5GK\"\x04\x10\xff\x1c]\x8b\xb7\xe5\xbc\x0fa\xba\xea\xa1/\xd0\xda\x1dz\x97\x01r\x9c\xea`\x14\xd7\xfeb\xa2\xed\x92m\xc3ka0\x7f\x11\x9dd\xed\xbc\xebZ\x9cX\x13;\xbfu\xba\x0b\xef\x00\n\x1aQ\x80\xe4\xb1\xde}\x89\xc8\x95(\xbc\xb7\x89\x9a\x1eF\xfdM\xa0\xd9\xde\x8f\x8ee\xe8\xd0\xd7u\xe3=\x12G\xe7mYj401a\xb2\x19\xf3\x9a\xfd\xa4H\xbfQ\x8a(5\xfc^(\xf0\xb5Z\x1ba7\xa2\xc7\x0c\xf7"),

            ("ge@äheim", b"\x01\x02\x03\x04\x05\x06\x07\x08", KDF_ENCRYPTION_KEY_ID, 100, 32, openssl::hash::MessageDigest::sha512(), b"\xb1J\x9f\x01\xbf\xd9\xdc\xe4\xc9\xd6m/\xe9\x93~_\xd9\xf1\xaf\xa5\x9e7\no\xa4\xfc\x81\xc1\xcc\x8e\xc8\xee"),

            // From https://cs.opensource.google/go/x/crypto/+/master:pkcs12/pbkdf_test.go
            ("sesame", b"\xff\xff\xff\xff\xff\xff\xff\xff", KDF_ENCRYPTION_KEY_ID, 2048, 24, openssl::hash::MessageDigest::sha1(), b"\x7c\xd9\xfd\x3e\x2b\x3b\xe7\x69\x1a\x44\xe3\xbe\xf0\xf9\xea\x0f\xb9\xb8\x97\xd4\xe3\x25\xd9\xd1"),
        ] {
            let result = kdf(password, salt, id, rounds, key_len, hash).map_err(|_| ()).unwrap();
            assert_eq!(result, expected_key);
        }
    }
}
