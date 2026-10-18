// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Hash functions from the crypto backend, behind the subset of the `openssl`
//! crate's hash API the rest of this crate uses: OpenSSL's own types, or
//! verified-garbage's under the same names.

#[cfg(feature = "openssl")]
pub use openssl::error::ErrorStack as Error;
#[cfg(feature = "openssl")]
pub use openssl::hash::{Hasher, MessageDigest};

#[cfg(not(feature = "openssl"))]
pub use self::vg::{Error, Hasher, MessageDigest};

#[cfg(not(feature = "openssl"))]
mod vg {
    use verified_garbage::hashes::{
        blake2b::Blake2b512, blake2s::Blake2s256, md5::Md5, sha1::Sha1, sha224::Sha224,
        sha256::Sha256, sha3, sha384::Sha384, sha512::Sha512, sha512_224::Sha512_224,
        sha512_256::Sha512_256, sm3::Sm3,
    };

    /// A failed operation (an invalid parameter): verified-garbage's hashes
    /// themselves cannot fail.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Error;

    impl std::fmt::Display for Error {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("invalid hash operation")
        }
    }

    impl std::error::Error for Error {}

    /// A hash algorithm verified-garbage implements.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum MessageDigest {
        Md5,
        Sha1,
        Sha224,
        Sha256,
        Sha384,
        Sha512,
        Sha512_224,
        Sha512_256,
        Sha3_224,
        Sha3_256,
        Sha3_384,
        Sha3_512,
        Shake128,
        Shake256,
        Blake2b512,
        Blake2s256,
        Sm3,
    }

    impl MessageDigest {
        pub fn md5() -> Self {
            MessageDigest::Md5
        }
        pub fn sha1() -> Self {
            MessageDigest::Sha1
        }
        pub fn sha224() -> Self {
            MessageDigest::Sha224
        }
        pub fn sha256() -> Self {
            MessageDigest::Sha256
        }
        pub fn sha384() -> Self {
            MessageDigest::Sha384
        }
        pub fn sha512() -> Self {
            MessageDigest::Sha512
        }

        /// The digest named as OpenSSL names it (cryptography's hash names,
        /// with BLAKE2's output size in bits appended).
        pub fn from_name(name: &str) -> Option<Self> {
            Some(match name {
                "md5" => MessageDigest::Md5,
                "sha1" => MessageDigest::Sha1,
                "sha224" => MessageDigest::Sha224,
                "sha256" => MessageDigest::Sha256,
                "sha384" => MessageDigest::Sha384,
                "sha512" => MessageDigest::Sha512,
                "sha512-224" => MessageDigest::Sha512_224,
                "sha512-256" => MessageDigest::Sha512_256,
                "sha3-224" => MessageDigest::Sha3_224,
                "sha3-256" => MessageDigest::Sha3_256,
                "sha3-384" => MessageDigest::Sha3_384,
                "sha3-512" => MessageDigest::Sha3_512,
                "shake128" => MessageDigest::Shake128,
                "shake256" => MessageDigest::Shake256,
                "blake2b512" => MessageDigest::Blake2b512,
                "blake2s256" => MessageDigest::Blake2s256,
                "sm3" => MessageDigest::Sm3,
                _ => return None,
            })
        }

        /// The size of a digest in bytes (OpenSSL's default for SHAKE).
        pub fn size(&self) -> usize {
            match self {
                MessageDigest::Md5 => 16,
                MessageDigest::Sha1 => 20,
                MessageDigest::Sha224 | MessageDigest::Sha512_224 | MessageDigest::Sha3_224 => 28,
                MessageDigest::Sha256
                | MessageDigest::Sha512_256
                | MessageDigest::Sha3_256
                | MessageDigest::Blake2s256
                | MessageDigest::Sm3
                | MessageDigest::Shake256 => 32,
                MessageDigest::Sha384 | MessageDigest::Sha3_384 => 48,
                MessageDigest::Sha512 | MessageDigest::Sha3_512 | MessageDigest::Blake2b512 => 64,
                MessageDigest::Shake128 => 16,
            }
        }

        /// The size of an input block in bytes.
        pub fn block_size(&self) -> usize {
            match self {
                MessageDigest::Md5
                | MessageDigest::Sha1
                | MessageDigest::Sha224
                | MessageDigest::Sha256
                | MessageDigest::Blake2s256
                | MessageDigest::Sm3 => 64,
                MessageDigest::Sha384
                | MessageDigest::Sha512
                | MessageDigest::Sha512_224
                | MessageDigest::Sha512_256
                | MessageDigest::Blake2b512 => 128,
                MessageDigest::Sha3_224 => 144,
                MessageDigest::Sha3_256 | MessageDigest::Shake256 => 136,
                MessageDigest::Sha3_384 => 104,
                MessageDigest::Sha3_512 => 72,
                MessageDigest::Shake128 => 168,
            }
        }
    }

    #[derive(Clone)]
    enum State {
        Md5(Md5),
        Sha1(Sha1),
        Sha224(Sha224),
        Sha256(Sha256),
        Sha384(Sha384),
        Sha512(Sha512),
        Sha512_224(Sha512_224),
        Sha512_256(Sha512_256),
        Sha3_224(sha3::Sha3_224),
        Sha3_256(sha3::Sha3_256),
        Sha3_384(sha3::Sha3_384),
        Sha3_512(sha3::Sha3_512),
        Shake128(sha3::Shake128),
        Shake256(sha3::Shake256),
        Blake2b512(Blake2b512),
        Blake2s256(Blake2s256),
        Sm3(Sm3),
    }

    /// A SHAKE output being squeezed.
    #[derive(Clone)]
    enum Reader {
        Shake128(sha3::Shake128Reader),
        Shake256(sha3::Shake256Reader),
    }

    /// A hash computation. As with OpenSSL's, an XOF can be squeezed
    /// repeatedly after absorbing, and a hasher can be reused after `finish`.
    #[derive(Clone)]
    pub struct Hasher {
        md: MessageDigest,
        state: Option<State>,
        reader: Option<Reader>,
    }

    fn new_state(md: MessageDigest) -> State {
        match md {
            MessageDigest::Md5 => State::Md5(Md5::new()),
            MessageDigest::Sha1 => State::Sha1(Sha1::new()),
            MessageDigest::Sha224 => State::Sha224(Sha224::new()),
            MessageDigest::Sha256 => State::Sha256(Sha256::new()),
            MessageDigest::Sha384 => State::Sha384(Sha384::new()),
            MessageDigest::Sha512 => State::Sha512(Sha512::new()),
            MessageDigest::Sha512_224 => State::Sha512_224(Sha512_224::new()),
            MessageDigest::Sha512_256 => State::Sha512_256(Sha512_256::new()),
            MessageDigest::Sha3_224 => State::Sha3_224(sha3::Sha3_224::new()),
            MessageDigest::Sha3_256 => State::Sha3_256(sha3::Sha3_256::new()),
            MessageDigest::Sha3_384 => State::Sha3_384(sha3::Sha3_384::new()),
            MessageDigest::Sha3_512 => State::Sha3_512(sha3::Sha3_512::new()),
            MessageDigest::Shake128 => State::Shake128(sha3::Shake128::new()),
            MessageDigest::Shake256 => State::Shake256(sha3::Shake256::new()),
            MessageDigest::Blake2b512 => State::Blake2b512(Blake2b512::new()),
            MessageDigest::Blake2s256 => State::Blake2s256(Blake2s256::new()),
            MessageDigest::Sm3 => State::Sm3(Sm3::new()),
        }
    }

    impl Hasher {
        pub fn new(md: MessageDigest) -> Result<Hasher, Error> {
            Ok(Hasher {
                md,
                state: Some(new_state(md)),
                reader: None,
            })
        }

        fn state(&mut self) -> &mut State {
            if self.state.is_none() {
                self.reader = None;
                self.state = Some(new_state(self.md));
            }
            self.state.as_mut().unwrap()
        }

        pub fn update(&mut self, data: &[u8]) -> Result<(), Error> {
            if self.reader.is_some() {
                // OpenSSL refuses to absorb after squeezing.
                return Err(Error);
            }
            match self.state() {
                State::Md5(h) => h.update(data),
                State::Sha1(h) => h.update(data),
                State::Sha224(h) => h.update(data),
                State::Sha256(h) => h.update(data),
                State::Sha384(h) => h.update(data),
                State::Sha512(h) => h.update(data),
                State::Sha512_224(h) => h.update(data),
                State::Sha512_256(h) => h.update(data),
                State::Sha3_224(h) => h.update(data),
                State::Sha3_256(h) => h.update(data),
                State::Sha3_384(h) => h.update(data),
                State::Sha3_512(h) => h.update(data),
                State::Shake128(h) => h.update(data),
                State::Shake256(h) => h.update(data),
                State::Blake2b512(h) => h.update(data),
                State::Blake2s256(h) => h.update(data),
                State::Sm3(h) => h.update(data),
            }
            Ok(())
        }

        /// The digest; the hasher then starts over, as OpenSSL's does. For
        /// SHAKE, the first `size()` bytes.
        pub fn finish(&mut self) -> Result<Vec<u8>, Error> {
            if matches!(self.md, MessageDigest::Shake128 | MessageDigest::Shake256) {
                let mut out = vec![0; self.md.size()];
                self.finish_xof(&mut out)?;
                return Ok(out);
            }
            self.state();
            self.reader = None;
            Ok(match self.state.take().unwrap() {
                State::Md5(h) => h.finalize().to_vec(),
                State::Sha1(h) => h.finalize().to_vec(),
                State::Sha224(h) => h.finalize().to_vec(),
                State::Sha256(h) => h.finalize().to_vec(),
                State::Sha384(h) => h.finalize().to_vec(),
                State::Sha512(h) => h.finalize().to_vec(),
                State::Sha512_224(h) => h.finalize().to_vec(),
                State::Sha512_256(h) => h.finalize().to_vec(),
                State::Sha3_224(h) => h.finalize().to_vec(),
                State::Sha3_256(h) => h.finalize().to_vec(),
                State::Sha3_384(h) => h.finalize().to_vec(),
                State::Sha3_512(h) => h.finalize().to_vec(),
                State::Blake2b512(h) => h.finalize().to_vec(),
                State::Blake2s256(h) => h.finalize().to_vec(),
                State::Sm3(h) => h.finalize().to_vec(),
                State::Shake128(_) | State::Shake256(_) => unreachable!(),
            })
        }

        /// The first `out.len()` bytes of an XOF's output; the hasher then
        /// starts over.
        pub fn finish_xof(&mut self, out: &mut [u8]) -> Result<(), Error> {
            if self.reader.is_some() {
                return Err(Error);
            }
            self.squeeze_xof(out)?;
            self.reader = None;
            self.state = None;
            Ok(())
        }

        /// The next `out.len()` bytes of an XOF's output; absorbing ends at
        /// the first squeeze.
        pub fn squeeze_xof(&mut self, out: &mut [u8]) -> Result<(), Error> {
            if self.reader.is_none() {
                let reader = match self.state() {
                    State::Shake128(h) => Reader::Shake128(h.clone().finalize_xof()),
                    State::Shake256(h) => Reader::Shake256(h.clone().finalize_xof()),
                    _ => return Err(Error),
                };
                self.reader = Some(reader);
            }
            match self.reader.as_mut().unwrap() {
                Reader::Shake128(r) => r.squeeze(out),
                Reader::Shake256(r) => r.squeeze(out),
            }
            Ok(())
        }
    }

    /// The digest of `data`.
    pub fn hash(md: MessageDigest, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut h = Hasher::new(md)?;
        h.update(data)?;
        h.finish()
    }
}

#[cfg(not(feature = "openssl"))]
pub use self::vg::hash;
#[cfg(feature = "openssl")]
pub fn hash(md: MessageDigest, data: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(openssl::hash::hash(md, data)?.to_vec())
}

/// The error for an invalid parameter (OpenSSL's is its current error stack).
pub fn invalid_parameter() -> Error {
    #[cfg(feature = "openssl")]
    {
        openssl::error::ErrorStack::get()
    }
    #[cfg(not(feature = "openssl"))]
    {
        Error
    }
}

