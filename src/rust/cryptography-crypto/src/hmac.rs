// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! HMAC from verified-garbage, behind the API of
//! `cryptography_openssl::hmac` that the rest of this crate uses (the OpenSSL
//! build uses that crate directly).

use verified_garbage::hashes::{
    md5::Md5, sha1::Sha1, sha224::Sha224, sha256::Sha256, sha384::Sha384, sha512::Sha512,
    sha512_224::Sha512_224, sha512_256::Sha512_256,
};
use verified_garbage::hmac::Hmac as VgHmac;

use crate::hash::{Error, MessageDigest};

/// A MAC: its bytes.
pub type DigestBytes = Vec<u8>;

#[derive(Clone)]
enum State {
    Md5(VgHmac<Md5>),
    Sha1(VgHmac<Sha1>),
    Sha224(VgHmac<Sha224>),
    Sha256(VgHmac<Sha256>),
    Sha384(VgHmac<Sha384>),
    Sha512(VgHmac<Sha512>),
    Sha512_224(VgHmac<Sha512_224>),
    Sha512_256(VgHmac<Sha512_256>),
}

/// Whether verified-garbage has HMAC with `md`: MD5, SHA-1 and SHA-2. (It
/// has no HMAC over SHA-3, BLAKE2 or SM3.)
pub fn supported(md: MessageDigest) -> bool {
    matches!(
        md,
        MessageDigest::Md5
            | MessageDigest::Sha1
            | MessageDigest::Sha224
            | MessageDigest::Sha256
            | MessageDigest::Sha384
            | MessageDigest::Sha512
            | MessageDigest::Sha512_224
            | MessageDigest::Sha512_256
    )
}

/// An HMAC computation. As with OpenSSL's, `finish` may be called once; a
/// computation is copied with `copy`.
#[derive(Clone)]
pub struct Hmac {
    state: Option<State>,
}

impl Hmac {
    /// Starts an HMAC computation with `key` and the hash `md`; fails if
    /// verified-garbage has no HMAC with `md` (see [`supported`]).
    pub fn new(key: &[u8], md: MessageDigest) -> Result<Hmac, Error> {
        let state = match md {
            MessageDigest::Md5 => State::Md5(VgHmac::new(key)),
            MessageDigest::Sha1 => State::Sha1(VgHmac::new(key)),
            MessageDigest::Sha224 => State::Sha224(VgHmac::new(key)),
            MessageDigest::Sha256 => State::Sha256(VgHmac::new(key)),
            MessageDigest::Sha384 => State::Sha384(VgHmac::new(key)),
            MessageDigest::Sha512 => State::Sha512(VgHmac::new(key)),
            MessageDigest::Sha512_224 => State::Sha512_224(VgHmac::new(key)),
            MessageDigest::Sha512_256 => State::Sha512_256(VgHmac::new(key)),
            _ => return Err(Error),
        };
        Ok(Hmac { state: Some(state) })
    }

    pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
        match self.state.as_mut().ok_or(Error)? {
            State::Md5(h) => h.update(data),
            State::Sha1(h) => h.update(data),
            State::Sha224(h) => h.update(data),
            State::Sha256(h) => h.update(data),
            State::Sha384(h) => h.update(data),
            State::Sha512(h) => h.update(data),
            State::Sha512_224(h) => h.update(data),
            State::Sha512_256(h) => h.update(data),
        }
        Ok(())
    }

    /// The MAC of everything absorbed. The computation is then finished:
    /// further calls fail.
    pub fn finish(&mut self) -> Result<DigestBytes, Error> {
        Ok(match self.state.take().ok_or(Error)? {
            State::Md5(h) => h.finalize().as_ref().to_vec(),
            State::Sha1(h) => h.finalize().as_ref().to_vec(),
            State::Sha224(h) => h.finalize().as_ref().to_vec(),
            State::Sha256(h) => h.finalize().as_ref().to_vec(),
            State::Sha384(h) => h.finalize().as_ref().to_vec(),
            State::Sha512(h) => h.finalize().as_ref().to_vec(),
            State::Sha512_224(h) => h.finalize().as_ref().to_vec(),
            State::Sha512_256(h) => h.finalize().as_ref().to_vec(),
        })
    }

    pub fn copy(&self) -> Result<Hmac, Error> {
        Ok(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::{supported, Hmac};
    use crate::hash::MessageDigest;

    #[test]
    fn test_streaming_matches_one_shot() {
        let data: Vec<u8> = (0..300u32).map(|i| i as u8).collect();
        for md in [
            MessageDigest::Md5,
            MessageDigest::Sha1,
            MessageDigest::Sha224,
            MessageDigest::Sha256,
            MessageDigest::Sha384,
            MessageDigest::Sha512,
            MessageDigest::Sha512_224,
            MessageDigest::Sha512_256,
        ] {
            assert!(supported(md));
            let mut one = Hmac::new(b"key", md).unwrap();
            one.update(&data).unwrap();
            let expected = one.finish().unwrap();
            assert_eq!(expected.len(), md.size());
            // Finished: further use fails.
            assert!(one.update(b"x").is_err());
            assert!(one.finish().is_err());

            let mut h = Hmac::new(b"key", md).unwrap();
            h.update(&data[..7]).unwrap();
            let mut copy = h.copy().unwrap();
            h.update(&data[7..]).unwrap();
            copy.update(&data[7..]).unwrap();
            assert_eq!(h.finish().unwrap(), expected);
            assert_eq!(copy.finish().unwrap(), expected);
        }
    }

    #[test]
    fn test_unsupported() {
        for md in [
            MessageDigest::Sha3_256,
            MessageDigest::Blake2b512,
            MessageDigest::Sm3,
            MessageDigest::Shake128,
        ] {
            assert!(!supported(md));
            assert!(Hmac::new(b"key", md).is_err());
        }
    }
}
