// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! CMAC from verified-garbage, behind the API of `cryptography_openssl::cmac`
//! that the rest of this crate uses (the OpenSSL build uses that crate
//! directly). verified-garbage has CMAC with AES and TDEA only.

use verified_garbage::cmac::aes::AesCmac;
use verified_garbage::cmac::triple_des::TripleDesCmac;

use crate::hash::Error;

/// A MAC: its bytes.
pub type DigestBytes = Vec<u8>;

/// A block cipher verified-garbage has CMAC with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmacCipher {
    /// AES-128, AES-192 or AES-256, by the key's length.
    Aes,
    /// Two- or three-key TDEA, by the key's length.
    TripleDes,
}

#[derive(Clone)]
enum State {
    Aes(AesCmac),
    TripleDes(TripleDesCmac),
}

/// A CMAC computation. As with OpenSSL's, `finish` may be called once; a
/// computation is copied with `copy`.
#[derive(Clone)]
pub struct Cmac {
    state: Option<State>,
}

impl Cmac {
    /// Starts a CMAC computation with `key` for `cipher`; fails if the key
    /// has a length the cipher does not take.
    pub fn new(key: &[u8], cipher: CmacCipher) -> Result<Cmac, Error> {
        let state = match cipher {
            CmacCipher::Aes => State::Aes(AesCmac::new(key).map_err(|_| Error)?),
            CmacCipher::TripleDes => State::TripleDes(TripleDesCmac::new(key).map_err(|_| Error)?),
        };
        Ok(Cmac { state: Some(state) })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.state.as_mut().ok_or(Error)? {
            State::Aes(c) => c.update(data),
            State::TripleDes(c) => c.update(data),
        }
        Ok(())
    }

    /// The MAC of everything absorbed. The computation is then finished:
    /// further calls fail.
    pub fn finish(&mut self) -> Result<DigestBytes, Error> {
        Ok(match self.state.take().ok_or(Error)? {
            State::Aes(c) => c.finalize().to_vec(),
            State::TripleDes(c) => c.finalize().to_vec(),
        })
    }

    pub fn copy(&self) -> Result<Cmac, Error> {
        Ok(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{Cmac, CmacCipher};

    #[test]
    fn test_streaming_matches_one_shot() {
        let data: Vec<u8> = (0..100u32).map(|i| (i * 7) as u8).collect();
        let key: Vec<u8> = (0..32u8).collect();
        for (cipher, key_len, expected) in [
            (
                CmacCipher::Aes,
                16,
                verified_garbage::cmac::aes::AesCmac::mac(&key[..16], &data)
                    .unwrap()
                    .to_vec(),
            ),
            (
                CmacCipher::Aes,
                32,
                verified_garbage::cmac::aes::AesCmac::mac(&key, &data)
                    .unwrap()
                    .to_vec(),
            ),
            (
                CmacCipher::TripleDes,
                24,
                verified_garbage::cmac::triple_des::TripleDesCmac::mac(&key[..24], &data)
                    .unwrap()
                    .to_vec(),
            ),
        ] {
            let mut c = Cmac::new(&key[..key_len], cipher).unwrap();
            c.update(&data[..33]).unwrap();
            let mut copy = c.copy().unwrap();
            c.update(&data[33..]).unwrap();
            copy.update(&data[33..]).unwrap();
            assert_eq!(c.finish().unwrap(), expected);
            assert_eq!(copy.finish().unwrap(), expected);
            assert!(c.finish().is_err());
            assert!(c.update(b"x").is_err());
        }
        assert!(Cmac::new(&key[..20], CmacCipher::Aes).is_err());
        assert!(Cmac::new(&key[..8], CmacCipher::TripleDes).is_err());
    }
}
