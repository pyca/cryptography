// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! The ciphers that encrypt keys (PKCS #8 PBES1/PBES2, PKCS #12 PBE and
//! legacy PEM encryption), with verified-garbage, and with PKCS #7 padding
//! for the block ciphers, as OpenSSL's `EVP_CIPHER`s add and remove it.

use verified_garbage::aes_cbc::AesCbc;
use verified_garbage::rc2_cbc::{Rc2CbcDecryptor, Rc2CbcEncryptor};
use verified_garbage::rc4::Rc4;
use verified_garbage::triple_des_cbc::TripleDesCbc;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Cipher {
    /// Single DES-CBC: Triple DES with three copies of the key (EDE with
    /// K1 = K2 = K3 is DES), as verified-garbage has no single DES.
    DesCbc,
    DesEde3Cbc,
    Aes128Cbc,
    Aes192Cbc,
    Aes256Cbc,
    /// RC2-CBC with a 40-bit key and 40 effective bits.
    Rc2_40Cbc,
    /// RC2-CBC with a 128-bit key and 128 effective bits.
    Rc2Cbc,
    Rc4,
}

/// Decryption failed: the key or IV has the wrong length for the cipher,
/// the ciphertext is not whole blocks, or the padding is wrong (which, with
/// a password-derived key, usually means the wrong password).
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct DecryptError;

impl Cipher {
    /// The key length, as OpenSSL's `EVP_CIPHER_key_length`.
    pub(crate) fn key_len(self) -> usize {
        match self {
            Cipher::DesCbc => 8,
            Cipher::DesEde3Cbc | Cipher::Aes192Cbc => 24,
            Cipher::Aes128Cbc | Cipher::Rc2Cbc | Cipher::Rc4 => 16,
            Cipher::Aes256Cbc => 32,
            Cipher::Rc2_40Cbc => 5,
        }
    }

    /// The block size, as OpenSSL's `EVP_CIPHER_block_size` (1 for RC4).
    pub(crate) fn block_size(self) -> usize {
        match self {
            Cipher::DesCbc | Cipher::DesEde3Cbc | Cipher::Rc2_40Cbc | Cipher::Rc2Cbc => 8,
            Cipher::Aes128Cbc | Cipher::Aes192Cbc | Cipher::Aes256Cbc => 16,
            Cipher::Rc4 => 1,
        }
    }

    /// The IV length (0 for RC4, which takes none).
    pub(crate) fn iv_len(self) -> usize {
        match self {
            Cipher::Rc4 => 0,
            _ => self.block_size(),
        }
    }

    /// Encrypts `data`, padded with PKCS #7 for block ciphers.
    ///
    /// # Panics
    ///
    /// If the key or IV does not have the cipher's length.
    pub(crate) fn encrypt(self, key: &[u8], iv: &[u8], data: &[u8]) -> Vec<u8> {
        assert_eq!(key.len(), self.key_len());
        assert_eq!(iv.len(), self.iv_len());
        let mut buf = data.to_vec();
        let bs = self.block_size();
        if bs > 1 {
            let pad = bs - data.len() % bs;
            buf.resize(data.len() + pad, pad as u8);
        }
        self.crypt(key, iv, &mut buf, false)
            .expect("lengths were checked");
        buf
    }

    /// Decrypts `data` and, for block ciphers, checks and removes its
    /// PKCS #7 padding.
    pub(crate) fn decrypt(
        self,
        key: &[u8],
        iv: &[u8],
        data: &[u8],
    ) -> Result<Vec<u8>, DecryptError> {
        if key.len() != self.key_len() || iv.len() != self.iv_len() {
            return Err(DecryptError);
        }
        let bs = self.block_size();
        if bs > 1 && (data.is_empty() || data.len() % bs != 0) {
            return Err(DecryptError);
        }
        let mut buf = data.to_vec();
        self.crypt(key, iv, &mut buf, true)?;
        if bs > 1 {
            let pad = usize::from(*buf.last().unwrap());
            if pad == 0
                || pad > bs
                || buf[buf.len() - pad..]
                    .iter()
                    .any(|&b| usize::from(b) != pad)
            {
                return Err(DecryptError);
            }
            buf.truncate(buf.len() - pad);
        }
        Ok(buf)
    }

    /// Encrypts or decrypts whole blocks in place, without padding.
    fn crypt(
        self,
        key: &[u8],
        iv: &[u8],
        buf: &mut [u8],
        decrypt: bool,
    ) -> Result<(), DecryptError> {
        match self {
            Cipher::DesCbc | Cipher::DesEde3Cbc => {
                let key = if self == Cipher::DesCbc {
                    [key, key, key].concat()
                } else {
                    key.to_vec()
                };
                let c = TripleDesCbc::new(&key).map_err(|_| DecryptError)?;
                let mut iv: [u8; 8] = iv.try_into().map_err(|_| DecryptError)?;
                if decrypt {
                    c.decrypt(&mut iv, buf)
                } else {
                    c.encrypt(&mut iv, buf)
                }
                .map_err(|_| DecryptError)
            }
            Cipher::Aes128Cbc | Cipher::Aes192Cbc | Cipher::Aes256Cbc => {
                let c = AesCbc::new(key).map_err(|_| DecryptError)?;
                let mut iv: [u8; 16] = iv.try_into().map_err(|_| DecryptError)?;
                if decrypt {
                    c.decrypt(&mut iv, buf)
                } else {
                    c.encrypt(&mut iv, buf)
                }
                .map_err(|_| DecryptError)
            }
            Cipher::Rc2_40Cbc | Cipher::Rc2Cbc => {
                let bits = key.len() * 8;
                let input = buf.to_vec();
                let written = if decrypt {
                    let mut c = Rc2CbcDecryptor::new_with_effective_bits(key, iv, bits)
                        .map_err(|_| DecryptError)?;
                    let n = c.update(&input, buf).map_err(|_| DecryptError)?;
                    c.finalize().map_err(|_| DecryptError)?;
                    n
                } else {
                    let mut c = Rc2CbcEncryptor::new_with_effective_bits(key, iv, bits)
                        .map_err(|_| DecryptError)?;
                    let n = c.update(&input, buf).map_err(|_| DecryptError)?;
                    c.finalize().map_err(|_| DecryptError)?;
                    n
                };
                if written == buf.len() {
                    Ok(())
                } else {
                    Err(DecryptError)
                }
            }
            Cipher::Rc4 => {
                let mut c = Rc4::new(key).map_err(|_| DecryptError)?;
                c.apply_keystream(buf);
                c.finalize();
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Cipher, DecryptError};

    const ALL: [Cipher; 8] = [
        Cipher::DesCbc,
        Cipher::DesEde3Cbc,
        Cipher::Aes128Cbc,
        Cipher::Aes192Cbc,
        Cipher::Aes256Cbc,
        Cipher::Rc2_40Cbc,
        Cipher::Rc2Cbc,
        Cipher::Rc4,
    ];

    #[test]
    fn test_round_trip() {
        for c in ALL {
            let key = vec![0x42; c.key_len()];
            let iv = vec![0x17; c.iv_len()];
            for len in [0, 1, 7, 8, 15, 16, 17, 100] {
                let data = vec![0xa5; len];
                let ct = c.encrypt(&key, &iv, &data);
                if c.block_size() > 1 {
                    assert_eq!(ct.len(), (len / c.block_size() + 1) * c.block_size());
                } else {
                    assert_eq!(ct.len(), len);
                }
                assert_eq!(c.decrypt(&key, &iv, &ct), Ok(data));
            }
        }
    }

    #[test]
    fn test_decrypt_errors() {
        for c in ALL {
            let key = vec![0x42; c.key_len()];
            let iv = vec![0x17; c.iv_len()];
            assert_eq!(c.decrypt(&key[1..], &iv, &[0; 16]), Err(DecryptError));
            assert_eq!(c.decrypt(&key, &[0x17; 3], &[0; 16]), Err(DecryptError));
            if c.block_size() > 1 {
                assert_eq!(c.decrypt(&key, &iv, &[]), Err(DecryptError));
                assert_eq!(c.decrypt(&key, &iv, &[0; 9]), Err(DecryptError));
                // A last block that decrypts to zeros: padding byte 0.
                let mut ct = c.encrypt(&key, &iv, &vec![0; c.block_size()]);
                ct.truncate(c.block_size());
                assert_eq!(c.decrypt(&key, &iv, &ct), Err(DecryptError));
                // ... to a padding byte larger than the block.
                let mut ct = c.encrypt(&key, &iv, &vec![0xff; c.block_size()]);
                ct.truncate(c.block_size());
                assert_eq!(c.decrypt(&key, &iv, &ct), Err(DecryptError));
                // ... to inconsistent padding bytes.
                let mut block = vec![0; c.block_size()];
                *block.last_mut().unwrap() = 2;
                let mut ct = c.encrypt(&key, &iv, &block);
                ct.truncate(c.block_size());
                assert_eq!(c.decrypt(&key, &iv, &ct), Err(DecryptError));
            }
        }
    }

    #[test]
    fn test_des_known_answer() {
        // FIPS 81 Appendix B, Table B1 (CBC mode): key 0123456789abcdef,
        // IV 1234567890abcdef, "Now is the time for all " (no padding: the
        // padding block is dropped).
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        let iv = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
        let ct = Cipher::DesCbc.encrypt(&key, &iv, b"Now is the time for all ");
        assert_eq!(
            &ct[..24],
            &[
                0xe5, 0xc7, 0xcd, 0xde, 0x87, 0x2b, 0xf2, 0x7c, 0x43, 0xe9, 0x34, 0x00, 0x8c, 0x38,
                0x9c, 0x0f, 0x68, 0x37, 0x88, 0x49, 0x9a, 0x7c, 0x05, 0xf6
            ]
        );
    }
}
