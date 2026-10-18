// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! The verified-garbage `CipherContext` behind `backend/ciphers.rs`: the
//! streaming interface of OpenSSL's `EVP_CIPHER_CTX` (updates of any length,
//! GCM's additional data and tag, `reset_nonce`), over verified-garbage's
//! modes, which take whole blocks (or end a message with a partial one).
//!
//! The modes fall into a few kinds, each buffered to stream:
//!
//! * ECB and CBC ([`Blocks`]) process whole blocks: an update outputs the
//!   whole blocks of what it and the earlier updates gave, and keeps the
//!   rest for the next one; finalizing with a partial block left is an error.
//!   RC2-CBC and Blowfish-ECB come as verified-garbage's own streaming
//!   encryptors and decryptors ([`Buffered`]), which buffer the same way.
//! * CFB (with whole-block segments), OFB and CTR ([`Segments`]) carry a
//!   block of state that only whole segments advance; a message may end with
//!   a partial segment. An update outputs every byte it is given: the bytes
//!   of a partial segment are processed as the end of a message, from a copy
//!   of the state, and kept; the next update processes them again with the
//!   bytes that follow (as the end of a message again, or as a whole segment
//!   that advances the state once they complete it), and outputs only the
//!   new bytes.
//! * CFB8, ChaCha20 and RC4 ([`Bytes`]) take pieces of any length.
//! * XTS processes each update as one data unit, as OpenSSL does.
//! * GCM uses verified-garbage's streaming encryptor and decryptor.

use verified_garbage::aes_cbc::AesCbc;
use verified_garbage::aes_cfb::AesCfb128;
use verified_garbage::aes_cfb8::AesCfb8;
use verified_garbage::aes_ctr::AesCtr;
use verified_garbage::aes_ecb::AesEcb;
use verified_garbage::aes_gcm::{AesGcm, AesGcmDecryptor, AesGcmEncryptor};
use verified_garbage::aes_ofb::AesOfb;
use verified_garbage::aes_xts::{self, AesXts};
use verified_garbage::blowfish_cbc::BlowfishCbc;
use verified_garbage::blowfish_cfb::BlowfishCfb64;
use verified_garbage::blowfish_ecb::{BlowfishEcbDecryptor, BlowfishEcbEncryptor};
use verified_garbage::blowfish_ofb::BlowfishOfb;
use verified_garbage::camellia_cbc::CamelliaCbc;
use verified_garbage::camellia_cfb::CamelliaCfb128;
use verified_garbage::camellia_ecb::CamelliaEcb;
use verified_garbage::camellia_ofb::CamelliaOfb;
use verified_garbage::cast5_cbc::Cast5Cbc;
use verified_garbage::cast5_cfb::Cast5Cfb64;
use verified_garbage::cast5_ecb::Cast5Ecb;
use verified_garbage::cast5_ofb::Cast5Ofb;
use verified_garbage::chacha20::ChaCha20;
use verified_garbage::idea_cbc::IdeaCbc;
use verified_garbage::idea_cfb::IdeaCfb64;
use verified_garbage::idea_ecb::IdeaEcb;
use verified_garbage::idea_ofb::IdeaOfb;
use verified_garbage::rc2_cbc::{Rc2CbcDecryptor, Rc2CbcEncryptor};
use verified_garbage::rc4::Rc4;
use verified_garbage::seed_cbc::SeedCbc;
use verified_garbage::seed_cfb::SeedCfb128;
use verified_garbage::seed_ecb::SeedEcb;
use verified_garbage::seed_ofb::SeedOfb;
use verified_garbage::sm4_cbc::Sm4Cbc;
use verified_garbage::sm4_cfb::Sm4Cfb128;
use verified_garbage::sm4_ctr::Sm4Ctr;
use verified_garbage::sm4_ecb::Sm4Ecb;
use verified_garbage::sm4_ofb::Sm4Ofb;
use verified_garbage::triple_des_cbc::TripleDesCbc;
use verified_garbage::triple_des_cfb::TripleDesCfb64;
use verified_garbage::triple_des_cfb8::TripleDesCfb8;
use verified_garbage::triple_des_ecb::TripleDesEcb;
use verified_garbage::triple_des_ofb::TripleDesOfb;

use pyo3::types::PyAnyMethods;

use crate::backend::cipher_registry::{self, Algorithm, Cipher, CipherMode};
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

/// The direction of a cipher context (OpenSSL's `openssl::symm::Mode`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Mode {
    Encrypt,
    Decrypt,
}

/// Whole blocks, in place, each call continuing from the last (ECB, CBC).
trait Blocks: Send + Sync {
    fn crypt(&mut self, blocks: &mut [u8]);
}

/// Segment modes (CFB, OFB, CTR): whole blocks advance the state; a partial
/// last segment is processed from a copy of it.
trait Segments: Send + Sync {
    fn crypt_full(&mut self, blocks: &mut [u8]);
    fn crypt_last(&self, partial: &mut [u8]);
    fn reset(&mut self, iv: &[u8]);
}

/// Pieces of any length (CFB8, ChaCha20, RC4).
trait Bytes: Send + Sync {
    fn crypt(&mut self, data: &mut [u8]);
    /// Restarts with another nonce (ChaCha20).
    fn reset(&mut self, nonce: &[u8]);
}

/// verified-garbage's own streaming block-mode encryptors and decryptors.
trait Buffered: Send + Sync {
    fn output_len(&self, input_len: usize) -> usize;
    fn update(&mut self, input: &[u8], output: &mut [u8]) -> usize;
    /// Whether the input was a whole number of blocks.
    fn finalize(self: Box<Self>) -> bool;
}

/// A mode's key and its chaining (or counter) block of `B` bytes.
struct Chained<K, const B: usize> {
    key: K,
    iv: [u8; B],
    encrypt: bool,
}

struct Ecb<K> {
    key: K,
    encrypt: bool,
}

macro_rules! impl_cbc {
    ($($t:ty: $b:literal),* $(,)?) => {$(
        impl Blocks for Chained<$t, $b> {
            fn crypt(&mut self, blocks: &mut [u8]) {
                // Only whole blocks are passed, which the modes accept.
                let ok = if self.encrypt {
                    self.key.encrypt(&mut self.iv, blocks).is_ok()
                } else {
                    self.key.decrypt(&mut self.iv, blocks).is_ok()
                };
                assert!(ok);
            }
        }
    )*};
}

impl_cbc!(AesCbc: 16, CamelliaCbc: 16, Sm4Cbc: 16, SeedCbc: 16, TripleDesCbc: 8,
    BlowfishCbc: 8, Cast5Cbc: 8, IdeaCbc: 8);

macro_rules! impl_ecb {
    ($($t:ty),* $(,)?) => {$(
        impl Blocks for Ecb<$t> {
            fn crypt(&mut self, blocks: &mut [u8]) {
                // Only whole blocks are passed, which the modes accept.
                let ok = if self.encrypt {
                    self.key.encrypt(blocks).is_ok()
                } else {
                    self.key.decrypt(blocks).is_ok()
                };
                assert!(ok);
            }
        }
    )*};
}

impl_ecb!(
    AesEcb,
    CamelliaEcb,
    Sm4Ecb,
    SeedEcb,
    TripleDesEcb,
    Cast5Ecb,
    IdeaEcb
);

macro_rules! impl_cfb {
    ($($t:ty: $b:literal),* $(,)?) => {$(
        impl Segments for Chained<$t, $b> {
            fn crypt_full(&mut self, blocks: &mut [u8]) {
                if self.encrypt {
                    self.key.encrypt(&mut self.iv, blocks);
                } else {
                    self.key.decrypt(&mut self.iv, blocks);
                }
            }
            fn crypt_last(&self, partial: &mut [u8]) {
                let mut iv = self.iv;
                if self.encrypt {
                    self.key.encrypt(&mut iv, partial);
                } else {
                    self.key.decrypt(&mut iv, partial);
                }
            }
            fn reset(&mut self, iv: &[u8]) {
                self.iv.copy_from_slice(iv);
            }
        }
    )*};
}

impl_cfb!(AesCfb128: 16, CamelliaCfb128: 16, Sm4Cfb128: 16, SeedCfb128: 16,
    TripleDesCfb64: 8, BlowfishCfb64: 8, Cast5Cfb64: 8, IdeaCfb64: 8);

macro_rules! impl_keystream {
    ($($t:ty: $b:literal),* $(,)?) => {$(
        impl Segments for Chained<$t, $b> {
            fn crypt_full(&mut self, blocks: &mut [u8]) {
                self.key.apply_keystream(&mut self.iv, blocks);
            }
            fn crypt_last(&self, partial: &mut [u8]) {
                let mut iv = self.iv;
                self.key.apply_keystream(&mut iv, partial);
            }
            fn reset(&mut self, iv: &[u8]) {
                self.iv.copy_from_slice(iv);
            }
        }
    )*};
}

impl_keystream!(AesOfb: 16, AesCtr: 16, CamelliaOfb: 16, Sm4Ofb: 16, Sm4Ctr: 16, SeedOfb: 16,
    TripleDesOfb: 8, BlowfishOfb: 8, Cast5Ofb: 8, IdeaOfb: 8);

macro_rules! impl_cfb8 {
    ($($t:ty: $b:literal),* $(,)?) => {$(
        impl Bytes for Chained<$t, $b> {
            fn crypt(&mut self, data: &mut [u8]) {
                if self.encrypt {
                    self.key.encrypt(&mut self.iv, data);
                } else {
                    self.key.decrypt(&mut self.iv, data);
                }
            }
            fn reset(&mut self, _nonce: &[u8]) {
                unreachable!("CFB8 has no nonce to reset")
            }
        }
    )*};
}

impl_cfb8!(AesCfb8: 16, TripleDesCfb8: 8);

impl Bytes for ChaCha20 {
    fn crypt(&mut self, data: &mut [u8]) {
        // The callers bound the bytes processed so that the block counter
        // never overflows (`chacha20_byte_limit` in `ciphers.rs`).
        self.apply_keystream(data);
    }
    fn reset(&mut self, nonce: &[u8]) {
        self.reset_nonce(nonce.try_into().unwrap());
    }
}

impl Bytes for Rc4 {
    fn crypt(&mut self, data: &mut [u8]) {
        self.apply_keystream(data);
    }
    fn reset(&mut self, _nonce: &[u8]) {
        unreachable!("RC4 has no nonce to reset")
    }
}

macro_rules! impl_buffered {
    ($($t:ty),* $(,)?) => {$(
        impl Buffered for $t {
            fn output_len(&self, input_len: usize) -> usize {
                <$t>::output_len(self, input_len)
            }
            fn update(&mut self, input: &[u8], output: &mut [u8]) -> usize {
                // `output` is at least `output_len(input.len())` bytes long.
                <$t>::update(self, input, output).unwrap()
            }
            fn finalize(self: Box<Self>) -> bool {
                <$t>::finalize(*self).is_ok()
            }
        }
    )*};
}

impl_buffered!(
    Rc2CbcEncryptor,
    Rc2CbcDecryptor,
    BlowfishEcbEncryptor,
    BlowfishEcbDecryptor
);

type GcmEncryptor<'a> = Option<AesGcmEncryptor<'a>>;
type GcmDecryptor<'a> = Option<AesGcmDecryptor<'a>>;

self_cell::self_cell!(
    /// An AES-GCM key and an encryption under it.
    struct GcmEncryption {
        owner: AesGcm,
        #[not_covariant]
        dependent: GcmEncryptor,
    }
);

self_cell::self_cell!(
    /// An AES-GCM key and a decryption under it.
    struct GcmDecryption {
        owner: AesGcm,
        #[not_covariant]
        dependent: GcmDecryptor,
    }
);

enum Engine {
    Blocks {
        mode: Box<dyn Blocks>,
        block_size: usize,
        pending: Vec<u8>,
    },
    Segments {
        mode: Box<dyn Segments>,
        block_size: usize,
        pending: Vec<u8>,
    },
    Bytes(Box<dyn Bytes>),
    Buffered(Option<Box<dyn Buffered>>),
    Xts {
        key: Box<AesXts>,
        tweak: [u8; 16],
        encrypt: bool,
    },
    GcmEncrypt {
        gcm: GcmEncryption,
        tag: Option<[u8; 16]>,
    },
    GcmDecrypt {
        gcm: GcmDecryption,
        tag: Option<Vec<u8>>,
    },
}

/// The tag lengths verified-garbage's AES-GCM verifies: those SP 800-38D
/// §5.2.1.2 allows.
fn gcm_tag_length_supported(len: usize) -> bool {
    matches!(len, 4 | 8 | 12..=16)
}

fn verify_gcm_tag(decryptor: AesGcmDecryptor<'_>, tag: &[u8]) -> bool {
    match tag.len() {
        4 => decryptor.finalize_truncated::<4>(tag.try_into().unwrap()),
        8 => decryptor.finalize_truncated::<8>(tag.try_into().unwrap()),
        12 => decryptor.finalize_truncated::<12>(tag.try_into().unwrap()),
        13 => decryptor.finalize_truncated::<13>(tag.try_into().unwrap()),
        14 => decryptor.finalize_truncated::<14>(tag.try_into().unwrap()),
        15 => decryptor.finalize_truncated::<15>(tag.try_into().unwrap()),
        16 => decryptor.finalize(tag.try_into().unwrap()),
        _ => return false,
    }
    .is_ok()
}

fn bad_parameters() -> CryptographyError {
    CryptographyError::VerifiedGarbage("invalid cipher key or IV")
}

fn block<const B: usize>(iv: Option<&[u8]>) -> CryptographyResult<[u8; B]> {
    iv.and_then(|iv| iv.try_into().ok())
        .ok_or_else(bad_parameters)
}

fn k<T, E>(r: Result<T, E>) -> CryptographyResult<T> {
    r.map_err(|_| bad_parameters())
}

fn key16(key: &[u8]) -> CryptographyResult<&[u8; 16]> {
    key.try_into().map_err(|_| bad_parameters())
}

/// Single DES: three-key TDEA with three equal keys.
fn des_key(key: &[u8]) -> Vec<u8> {
    key.repeat(3)
}

macro_rules! chained {
    ($key:expr, $b:literal, $iv:expr, $encrypt:expr) => {
        Box::new(Chained {
            key: $key,
            iv: block::<$b>($iv)?,
            encrypt: $encrypt,
        })
    };
}

impl Engine {
    fn new(
        cipher: Cipher,
        key: &[u8],
        iv: Option<&[u8]>,
        side: Mode,
    ) -> CryptographyResult<Engine> {
        use Algorithm as A;
        use CipherMode as M;

        let encrypt = side == Mode::Encrypt;
        let block_size = cipher.algorithm.block_size();

        let blocks = |mode: Box<dyn Blocks>| Engine::Blocks {
            mode,
            block_size,
            pending: Vec::new(),
        };
        let segments = |mode: Box<dyn Segments>| Engine::Segments {
            mode,
            block_size,
            pending: Vec::new(),
        };
        macro_rules! ecb {
            ($key:expr) => {
                Box::new(Ecb { key: $key, encrypt })
            };
        }

        Ok(match (cipher.algorithm, cipher.mode) {
            (A::Aes, M::Cbc) => blocks(chained!(k(AesCbc::new(key))?, 16, iv, encrypt)),
            (A::Aes, M::Ecb) => blocks(ecb!(k(AesEcb::new(key))?)),
            (A::Aes, M::Cfb) => segments(chained!(k(AesCfb128::new(key))?, 16, iv, encrypt)),
            (A::Aes, M::Cfb8) => Engine::Bytes(chained!(k(AesCfb8::new(key))?, 16, iv, encrypt)),
            (A::Aes, M::Ofb) => segments(chained!(k(AesOfb::new(key))?, 16, iv, encrypt)),
            (A::Aes, M::Ctr) => segments(chained!(k(AesCtr::new(key))?, 16, iv, encrypt)),
            (A::Aes, M::Xts) => {
                let key = AesXts::new(key).map_err(|e| match e {
                    aes_xts::Error::EqualKeyHalves => {
                        CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
                            "In XTS mode duplicated keys are not allowed",
                        ))
                    }
                    _ => bad_parameters(),
                })?;
                Engine::Xts {
                    key: Box::new(key),
                    tweak: block::<16>(iv)?,
                    encrypt,
                }
            }
            (A::Aes, M::Gcm) => {
                let nonce = iv.ok_or_else(bad_parameters)?;
                let gcm = k(AesGcm::new(key))?;
                if encrypt {
                    Engine::GcmEncrypt {
                        gcm: k(GcmEncryption::try_new(gcm, |gcm| {
                            gcm.encryptor(nonce).map(Some)
                        }))?,
                        tag: None,
                    }
                } else {
                    Engine::GcmDecrypt {
                        gcm: k(GcmDecryption::try_new(gcm, |gcm| {
                            gcm.decryptor(nonce).map(Some)
                        }))?,
                        tag: None,
                    }
                }
            }

            (A::TripleDes, M::Cbc) => blocks(chained!(k(TripleDesCbc::new(key))?, 8, iv, encrypt)),
            (A::Des, M::Cbc) => blocks(chained!(
                k(TripleDesCbc::new(&des_key(key)))?,
                8,
                iv,
                encrypt
            )),
            (A::TripleDes, M::Ecb) => blocks(ecb!(k(TripleDesEcb::new(key))?)),
            (A::TripleDes, M::Cfb) => {
                segments(chained!(k(TripleDesCfb64::new(key))?, 8, iv, encrypt))
            }
            (A::TripleDes, M::Cfb8) => {
                Engine::Bytes(chained!(k(TripleDesCfb8::new(key))?, 8, iv, encrypt))
            }
            (A::TripleDes, M::Ofb) => {
                segments(chained!(k(TripleDesOfb::new(key))?, 8, iv, encrypt))
            }

            (A::Camellia, M::Cbc) => blocks(chained!(k(CamelliaCbc::new(key))?, 16, iv, encrypt)),
            (A::Camellia, M::Ecb) => blocks(ecb!(k(CamelliaEcb::new(key))?)),
            (A::Camellia, M::Cfb) => {
                segments(chained!(k(CamelliaCfb128::new(key))?, 16, iv, encrypt))
            }
            (A::Camellia, M::Ofb) => segments(chained!(k(CamelliaOfb::new(key))?, 16, iv, encrypt)),

            (A::Sm4, M::Cbc) => blocks(chained!(Sm4Cbc::new(key16(key)?), 16, iv, encrypt)),
            (A::Sm4, M::Ecb) => blocks(ecb!(Sm4Ecb::new(key16(key)?))),
            (A::Sm4, M::Cfb) => segments(chained!(Sm4Cfb128::new(key16(key)?), 16, iv, encrypt)),
            (A::Sm4, M::Ofb) => segments(chained!(Sm4Ofb::new(key16(key)?), 16, iv, encrypt)),
            (A::Sm4, M::Ctr) => segments(chained!(Sm4Ctr::new(key16(key)?), 16, iv, encrypt)),

            (A::Seed, M::Cbc) => blocks(chained!(k(SeedCbc::new(key))?, 16, iv, encrypt)),
            (A::Seed, M::Ecb) => blocks(ecb!(SeedEcb::new(key16(key)?))),
            (A::Seed, M::Cfb) => segments(chained!(k(SeedCfb128::new(key))?, 16, iv, encrypt)),
            (A::Seed, M::Ofb) => segments(chained!(k(SeedOfb::new(key))?, 16, iv, encrypt)),

            (A::Blowfish, M::Cbc) => blocks(chained!(k(BlowfishCbc::new(key))?, 8, iv, encrypt)),
            (A::Blowfish, M::Ecb) => {
                let b: Box<dyn Buffered> = if encrypt {
                    Box::new(k(BlowfishEcbEncryptor::new(key))?)
                } else {
                    Box::new(k(BlowfishEcbDecryptor::new(key))?)
                };
                Engine::Buffered(Some(b))
            }
            (A::Blowfish, M::Cfb) => {
                segments(chained!(k(BlowfishCfb64::new(key))?, 8, iv, encrypt))
            }
            (A::Blowfish, M::Ofb) => segments(chained!(k(BlowfishOfb::new(key))?, 8, iv, encrypt)),

            (A::Cast5, M::Cbc) => blocks(chained!(k(Cast5Cbc::new(key))?, 8, iv, encrypt)),
            (A::Cast5, M::Ecb) => blocks(ecb!(k(Cast5Ecb::new(key))?)),
            (A::Cast5, M::Cfb) => segments(chained!(k(Cast5Cfb64::new(key))?, 8, iv, encrypt)),
            (A::Cast5, M::Ofb) => segments(chained!(k(Cast5Ofb::new(key))?, 8, iv, encrypt)),

            (A::Idea, M::Cbc) => blocks(chained!(k(IdeaCbc::new(key))?, 8, iv, encrypt)),
            (A::Idea, M::Ecb) => blocks(ecb!(k(IdeaEcb::new(key))?)),
            (A::Idea, M::Cfb) => segments(chained!(k(IdeaCfb64::new(key))?, 8, iv, encrypt)),
            (A::Idea, M::Ofb) => segments(chained!(k(IdeaOfb::new(key))?, 8, iv, encrypt)),

            (A::Rc2, M::Cbc) => {
                let iv = iv.ok_or_else(bad_parameters)?;
                let b: Box<dyn Buffered> = if encrypt {
                    Box::new(k(Rc2CbcEncryptor::new(key, iv))?)
                } else {
                    Box::new(k(Rc2CbcDecryptor::new(key, iv))?)
                };
                Engine::Buffered(Some(b))
            }
            (A::Rc4, M::Stream) => Engine::Bytes(Box::new(k(Rc4::new(key))?)),
            (A::ChaCha20, M::Stream) => {
                let key: &[u8; 32] = key.try_into().map_err(|_| bad_parameters())?;
                Engine::Bytes(Box::new(ChaCha20::new(key, &block::<16>(iv)?)))
            }
            _ => return Err(bad_parameters()),
        })
    }

    /// OpenSSL's block size for the cipher: the cipher's for the modes that
    /// output whole blocks, 1 for the others.
    fn block_size(&self) -> usize {
        match self {
            Engine::Blocks { block_size, .. } => *block_size,
            Engine::Buffered(_) => 8,
            _ => 1,
        }
    }

    /// The number of bytes the next update of `input_len` bytes outputs.
    fn output_len(&self, input_len: usize) -> usize {
        match self {
            Engine::Blocks {
                block_size,
                pending,
                ..
            } => (pending.len() + input_len) / block_size * block_size,
            Engine::Buffered(Some(b)) => b.output_len(input_len),
            Engine::Buffered(None) => 0,
            _ => input_len,
        }
    }

    /// Processes `data` into `out`, which is at least
    /// `output_len(data.len())` bytes long, and returns the number of bytes
    /// written.
    fn update(&mut self, data: &[u8], out: &mut [u8]) -> CryptographyResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        match self {
            Engine::Blocks {
                mode,
                block_size,
                pending,
            } => {
                let bs = *block_size;
                let n = (pending.len() + data.len()) / bs * bs;
                if n == 0 {
                    pending.extend_from_slice(data);
                    return Ok(0);
                }
                // The whole blocks: the pending bytes, then the start of
                // `data`; the rest of `data` is pending.
                let from_data = n - pending.len();
                out[..pending.len()].copy_from_slice(pending);
                out[pending.len()..n].copy_from_slice(&data[..from_data]);
                mode.crypt(&mut out[..n]);
                pending.clear();
                pending.extend_from_slice(&data[from_data..]);
                Ok(n)
            }
            Engine::Segments {
                mode,
                block_size,
                pending,
            } => {
                let bs = *block_size;
                let mut done = 0;
                if !pending.is_empty() {
                    // Complete (or extend) the partial segment, reprocess it,
                    // and output its new bytes.
                    let take = (bs - pending.len()).min(data.len());
                    pending.extend_from_slice(&data[..take]);
                    let mut segment = pending.clone();
                    if segment.len() == bs {
                        mode.crypt_full(&mut segment);
                        pending.clear();
                    } else {
                        mode.crypt_last(&mut segment);
                    }
                    out[..take].copy_from_slice(&segment[segment.len() - take..]);
                    done = take;
                }
                let rest = &data[done..];
                let whole = rest.len() / bs * bs;
                out[done..done + whole].copy_from_slice(&rest[..whole]);
                mode.crypt_full(&mut out[done..done + whole]);
                let tail = &rest[whole..];
                if !tail.is_empty() {
                    pending.extend_from_slice(tail);
                    let out_tail = &mut out[done + whole..data.len()];
                    out_tail.copy_from_slice(tail);
                    mode.crypt_last(out_tail);
                }
                Ok(data.len())
            }
            Engine::Bytes(mode) => {
                out[..data.len()].copy_from_slice(data);
                mode.crypt(&mut out[..data.len()]);
                Ok(data.len())
            }
            Engine::Buffered(b) => {
                let b = b.as_mut().ok_or_else(exceptions::already_finalized_error)?;
                Ok(b.update(data, out))
            }
            Engine::Xts {
                key,
                tweak,
                encrypt,
            } => {
                let out = &mut out[..data.len()];
                out.copy_from_slice(data);
                let result = if *encrypt {
                    key.encrypt(tweak, out)
                } else {
                    key.decrypt(tweak, out)
                };
                result.map_err(|_| {
                    pyo3::exceptions::PyValueError::new_err(
                        "In XTS mode you must supply at least a full block in the first update call. For AES this is 16 bytes."
                    )
                })?;
                Ok(data.len())
            }
            Engine::GcmEncrypt { gcm, .. } => {
                let out = &mut out[..data.len()];
                out.copy_from_slice(data);
                gcm.with_dependent_mut(|_, e| match e {
                    Some(e) => e.update(out).map_err(|_| bad_parameters()),
                    None => Err(exceptions::already_finalized_error()),
                })?;
                Ok(data.len())
            }
            Engine::GcmDecrypt { gcm, .. } => {
                let out = &mut out[..data.len()];
                out.copy_from_slice(data);
                gcm.with_dependent_mut(|_, d| match d {
                    Some(d) => d.update(out).map_err(|_| bad_parameters()),
                    None => Err(exceptions::already_finalized_error()),
                })?;
                Ok(data.len())
            }
        }
    }

    fn update_aad(&mut self, data: &[u8]) -> CryptographyResult<()> {
        match self {
            Engine::GcmEncrypt { gcm, .. } => gcm.with_dependent_mut(|_, e| match e {
                Some(e) => e.update_aad(data).map_err(|_| bad_parameters()),
                None => Err(exceptions::already_finalized_error()),
            }),
            Engine::GcmDecrypt { gcm, .. } => gcm.with_dependent_mut(|_, d| match d {
                Some(d) => d.update_aad(data).map_err(|_| bad_parameters()),
                None => Err(exceptions::already_finalized_error()),
            }),
            _ => Err(CryptographyError::VerifiedGarbage(
                "additional data for a mode without authentication",
            )),
        }
    }

    /// Ends the message. Fails with `None` if the input was not a whole
    /// number of blocks (for the modes that need one) or, for GCM
    /// decryption, if the tag does not match.
    fn finalize(&mut self) -> Result<(), ()> {
        match self {
            Engine::Blocks { pending, .. } => {
                if pending.is_empty() {
                    Ok(())
                } else {
                    Err(())
                }
            }
            Engine::Buffered(b) => match b.take().map(|b| b.finalize()) {
                Some(true) => Ok(()),
                _ => Err(()),
            },
            Engine::Segments { .. } | Engine::Bytes(_) | Engine::Xts { .. } => Ok(()),
            Engine::GcmEncrypt { gcm, tag } => {
                let t = gcm.with_dependent_mut(|_, e| e.take().map(|e| e.finalize()));
                *tag = t;
                t.map(|_| ()).ok_or(())
            }
            Engine::GcmDecrypt { gcm, tag } => {
                let tag = tag.as_deref().ok_or(())?;
                let ok = gcm.with_dependent_mut(|_, d| match d.take() {
                    Some(d) => verify_gcm_tag(d, tag),
                    None => false,
                });
                if ok {
                    Ok(())
                } else {
                    Err(())
                }
            }
        }
    }
}

pub(crate) struct CipherContext {
    engine: Engine,
    pub(crate) py_mode: pyo3::Py<pyo3::PyAny>,
    py_algorithm: pyo3::Py<pyo3::PyAny>,
    /// The length of the IV or nonce `reset_nonce` takes.
    nonce_len: usize,
}

impl CipherContext {
    pub(crate) fn new(
        py: pyo3::Python<'_>,
        algorithm: pyo3::Bound<'_, pyo3::PyAny>,
        mode: pyo3::Bound<'_, pyo3::PyAny>,
        side: Mode,
    ) -> CryptographyResult<CipherContext> {
        let cipher =
            match cipher_registry::get_cipher(py, algorithm.clone(), mode.get_type().into_any())? {
                Some(c) => c,
                None => {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            format!(
                                "cipher {} in {} mode is not supported ",
                                algorithm.getattr(pyo3::intern!(py, "name"))?,
                                if mode.is_truthy()? {
                                    mode.getattr(pyo3::intern!(py, "name"))?
                                } else {
                                    mode
                                }
                            ),
                            exceptions::Reasons::UNSUPPORTED_CIPHER,
                        )),
                    ))
                }
            };

        let iv_nonce = if mode.is_instance(&types::MODE_WITH_INITIALIZATION_VECTOR.get(py)?)? {
            Some(
                mode.getattr(pyo3::intern!(py, "initialization_vector"))?
                    .extract::<CffiBuf<'_>>()?,
            )
        } else if mode.is_instance(&types::MODE_WITH_TWEAK.get(py)?)? {
            Some(
                mode.getattr(pyo3::intern!(py, "tweak"))?
                    .extract::<CffiBuf<'_>>()?,
            )
        } else if mode.is_instance(&types::MODE_WITH_NONCE.get(py)?)? {
            Some(
                mode.getattr(pyo3::intern!(py, "nonce"))?
                    .extract::<CffiBuf<'_>>()?,
            )
        } else if algorithm.is_instance(&types::CHACHA20.get(py)?)? {
            Some(
                algorithm
                    .getattr(pyo3::intern!(py, "nonce"))?
                    .extract::<CffiBuf<'_>>()?,
            )
        } else {
            None
        };

        let key = algorithm
            .getattr(pyo3::intern!(py, "key"))?
            .extract::<CffiBuf<'_>>()?;

        let engine = Engine::new(
            cipher,
            key.as_bytes(),
            iv_nonce.as_ref().map(|b| b.as_bytes()),
            side,
        )?;
        let nonce_len = match cipher.algorithm {
            Algorithm::ChaCha20 => 16,
            _ => cipher.algorithm.block_size(),
        };

        Ok(CipherContext {
            engine,
            py_mode: mode.into(),
            py_algorithm: algorithm.into(),
            nonce_len,
        })
    }

    pub(crate) fn reset_nonce(
        &mut self,
        py: pyo3::Python<'_>,
        nonce: &[u8],
    ) -> CryptographyResult<()> {
        if !self
            .py_mode
            .bind(py)
            .is_instance(&types::MODE_WITH_NONCE.get(py)?)?
            && !self
                .py_algorithm
                .bind(py)
                .is_instance(&types::CHACHA20.get(py)?)?
        {
            return Err(CryptographyError::from(
                exceptions::UnsupportedAlgorithm::new_err((
                    "This algorithm or mode does not support resetting the nonce.",
                    exceptions::Reasons::UNSUPPORTED_CIPHER,
                )),
            ));
        }
        if nonce.len() != self.nonce_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "Nonce must be {} bytes long",
                    self.nonce_len
                )),
            ));
        }
        match &mut self.engine {
            Engine::Segments { mode, pending, .. } => {
                mode.reset(nonce);
                pending.clear();
            }
            Engine::Bytes(mode) => mode.reset(nonce),
            _ => return Err(bad_parameters()),
        }
        Ok(())
    }

    pub(crate) fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        data: &[u8],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let n = self.engine.output_len(data.len());
        let mut buf = vec![0; data.len() + self.engine.block_size() - 1];
        let written = self.update_into(py, data, &mut buf)?;
        assert_eq!(written, n);
        Ok(pyo3::types::PyBytes::new(py, &buf[..written]))
    }

    pub(crate) fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        data: &[u8],
        buf: &mut [u8],
    ) -> CryptographyResult<usize> {
        let block_size = self.engine.block_size();
        if buf.len() < (data.len() + block_size - 1) {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be at least {} bytes for this payload",
                    data.len() + block_size - 1
                )),
            ));
        }
        crate::buf::check_no_overlap(data, buf)?;

        let engine = &mut self.engine;
        crate::backend::run_with_gil_detached(py, data.len(), || engine.update(data, buf))
    }

    pub(crate) fn authenticate_additional_data(
        &mut self,
        py: pyo3::Python<'_>,
        data: &[u8],
    ) -> CryptographyResult<()> {
        let engine = &mut self.engine;
        crate::backend::run_with_gil_detached(py, data.len(), || engine.update_aad(data))
    }

    pub(crate) fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if self.engine.finalize().is_err() {
            // For authenticated modes, the only way finalize can fail is a
            // tag mismatch.
            if self
                .py_mode
                .bind(py)
                .is_instance(&types::MODE_WITH_AUTHENTICATION_TAG.get(py)?)?
            {
                return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
            }
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(
                    "The length of the provided data is not a multiple of the block length.",
                ),
            ));
        }
        Ok(pyo3::types::PyBytes::new(py, b""))
    }

    /// Writes the tag of a finished GCM encryption (its first `buf.len()`
    /// bytes).
    pub(crate) fn tag(&mut self, buf: &mut [u8]) -> CryptographyResult<()> {
        match &self.engine {
            Engine::GcmEncrypt { tag: Some(tag), .. } if buf.len() <= tag.len() => {
                buf.copy_from_slice(&tag[..buf.len()]);
                Ok(())
            }
            _ => Err(CryptographyError::VerifiedGarbage("no tag to get")),
        }
    }

    /// Sets the tag a GCM decryption is checked against.
    pub(crate) fn set_tag(&mut self, tag: &[u8]) -> CryptographyResult<()> {
        match &mut self.engine {
            Engine::GcmDecrypt { tag: t, .. } => {
                if !gcm_tag_length_supported(tag.len()) {
                    return Err(CryptographyError::from(
                        exceptions::UnsupportedAlgorithm::new_err((
                            "Authentication tags of 4, 8, 12, 13, 14, 15 or 16 bytes are the only ones supported by this backend.",
                            exceptions::Reasons::UNSUPPORTED_CIPHER,
                        )),
                    ));
                }
                *t = Some(tag.to_vec());
                Ok(())
            }
            _ => Err(CryptographyError::VerifiedGarbage("no tag to set")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Engine, Mode};
    use crate::backend::cipher_registry::{Algorithm, Cipher, CipherMode};

    fn bytes(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    /// Runs `data` through a new engine in updates of the lengths in
    /// `chunks` (cycled), then finalizes it.
    fn stream(
        cipher: Cipher,
        key: &[u8],
        iv: Option<&[u8]>,
        side: Mode,
        data: &[u8],
        chunks: &[usize],
    ) -> Result<Vec<u8>, ()> {
        let mut e = Engine::new(cipher, key, iv, side).unwrap_or_else(|_| panic!());
        let mut out = Vec::new();
        let mut rest = data;
        for &c in chunks.iter().cycle() {
            if rest.is_empty() {
                break;
            }
            let (now, later) = rest.split_at(c.min(rest.len()));
            let mut buf = vec![0; now.len() + e.block_size() - 1];
            let expected = e.output_len(now.len());
            let n = e.update(now, &mut buf).unwrap_or_else(|_| panic!());
            assert_eq!(n, expected);
            out.extend_from_slice(&buf[..n]);
            rest = later;
        }
        e.finalize()?;
        Ok(out)
    }

    const CHUNKINGS: &[&[usize]] = &[&[1], &[3, 15, 16, 17], &[7, 1, 33], &[64], &[1000]];

    fn check(cipher: Cipher, key: &[u8], iv: Option<&[u8]>, data: &[u8], expected: &[u8]) {
        for chunks in CHUNKINGS {
            let ct = stream(cipher, key, iv, Mode::Encrypt, data, chunks).unwrap();
            assert_eq!(ct, expected, "{cipher:?} encryption, chunks {chunks:?}");
            let pt = stream(cipher, key, iv, Mode::Decrypt, expected, chunks).unwrap();
            assert_eq!(pt, data, "{cipher:?} decryption, chunks {chunks:?}");
        }
    }

    fn cipher(algorithm: Algorithm, mode: CipherMode) -> Cipher {
        Cipher { algorithm, mode }
    }

    #[test]
    fn test_aes_segment_modes() {
        let key = bytes(16, 1);
        let iv: [u8; 16] = bytes(16, 2).try_into().unwrap();
        for len in [0, 1, 15, 16, 17, 100, 257] {
            let data = bytes(len, 3);

            let mut expected = data.clone();
            verified_garbage::aes_ctr::AesCtr::new(&key)
                .unwrap()
                .apply_keystream(&mut iv.clone(), &mut expected);
            check(
                cipher(Algorithm::Aes, CipherMode::Ctr),
                &key,
                Some(&iv),
                &data,
                &expected,
            );

            let mut expected = data.clone();
            verified_garbage::aes_ofb::AesOfb::new(&key)
                .unwrap()
                .apply_keystream(&mut iv.clone(), &mut expected);
            check(
                cipher(Algorithm::Aes, CipherMode::Ofb),
                &key,
                Some(&iv),
                &data,
                &expected,
            );

            let mut expected = data.clone();
            verified_garbage::aes_cfb::AesCfb128::new(&key)
                .unwrap()
                .encrypt(&mut iv.clone(), &mut expected);
            check(
                cipher(Algorithm::Aes, CipherMode::Cfb),
                &key,
                Some(&iv),
                &data,
                &expected,
            );

            let mut expected = data.clone();
            verified_garbage::aes_cfb8::AesCfb8::new(&key)
                .unwrap()
                .encrypt(&mut iv.clone(), &mut expected);
            check(
                cipher(Algorithm::Aes, CipherMode::Cfb8),
                &key,
                Some(&iv),
                &data,
                &expected,
            );
        }
    }

    #[test]
    fn test_64_bit_segment_modes() {
        let key = bytes(24, 4);
        let iv: [u8; 8] = bytes(8, 5).try_into().unwrap();
        for len in [0, 1, 7, 8, 9, 100] {
            let data = bytes(len, 6);
            let mut expected = data.clone();
            verified_garbage::triple_des_cfb::TripleDesCfb64::new(&key)
                .unwrap()
                .encrypt(&mut iv.clone(), &mut expected);
            check(
                cipher(Algorithm::TripleDes, CipherMode::Cfb),
                &key,
                Some(&iv),
                &data,
                &expected,
            );

            let mut expected = data.clone();
            verified_garbage::blowfish_ofb::BlowfishOfb::new(&key[..16])
                .unwrap()
                .apply_keystream(&mut iv.clone(), &mut expected);
            check(
                cipher(Algorithm::Blowfish, CipherMode::Ofb),
                &key[..16],
                Some(&iv),
                &data,
                &expected,
            );
        }
    }

    #[test]
    fn test_block_modes() {
        let key = bytes(32, 7);
        let iv: [u8; 16] = bytes(16, 8).try_into().unwrap();
        for len in [0, 16, 48, 160] {
            let data = bytes(len, 9);

            let mut expected = data.clone();
            verified_garbage::aes_cbc::AesCbc::new(&key)
                .unwrap()
                .encrypt(&mut iv.clone(), &mut expected)
                .unwrap();
            check(
                cipher(Algorithm::Aes, CipherMode::Cbc),
                &key,
                Some(&iv),
                &data,
                &expected,
            );

            let mut expected = data.clone();
            verified_garbage::aes_ecb::AesEcb::new(&key)
                .unwrap()
                .encrypt(&mut expected)
                .unwrap();
            check(
                cipher(Algorithm::Aes, CipherMode::Ecb),
                &key,
                None,
                &data,
                &expected,
            );

            // RC2-CBC and Blowfish-ECB are verified-garbage's own streaming
            // encryptors.
            let mut expected = vec![0; len];
            let mut rc2 =
                verified_garbage::rc2_cbc::Rc2CbcEncryptor::new(&key[..16], &iv[..8]).unwrap();
            assert_eq!(rc2.update(&data, &mut expected).unwrap(), len);
            rc2.finalize().unwrap();
            check(
                cipher(Algorithm::Rc2, CipherMode::Cbc),
                &key[..16],
                Some(&iv[..8]),
                &data,
                &expected,
            );

            let mut expected = vec![0; len];
            let mut bf =
                verified_garbage::blowfish_ecb::BlowfishEcbEncryptor::new(&key[..16]).unwrap();
            assert_eq!(bf.update(&data, &mut expected).unwrap(), len);
            bf.finalize().unwrap();
            check(
                cipher(Algorithm::Blowfish, CipherMode::Ecb),
                &key[..16],
                None,
                &data,
                &expected,
            );
        }

        // Single DES is TDEA with three equal keys.
        let data = bytes(24, 10);
        let mut expected = data.clone();
        verified_garbage::triple_des_cbc::TripleDesCbc::new(&key[..8].repeat(3))
            .unwrap()
            .encrypt(&mut iv[..8].try_into().unwrap(), &mut expected)
            .unwrap();
        check(
            cipher(Algorithm::Des, CipherMode::Cbc),
            &key[..8],
            Some(&iv[..8]),
            &data,
            &expected,
        );
    }

    #[test]
    fn test_block_modes_partial_block() {
        let key = bytes(16, 11);
        let iv = bytes(16, 12);
        for c in [
            cipher(Algorithm::Aes, CipherMode::Cbc),
            cipher(Algorithm::Aes, CipherMode::Ecb),
            cipher(Algorithm::Blowfish, CipherMode::Ecb),
            cipher(Algorithm::Rc2, CipherMode::Cbc),
        ] {
            let iv = match c.mode {
                CipherMode::Cbc => Some(&iv[..c.algorithm.block_size()]),
                _ => None,
            };
            for side in [Mode::Encrypt, Mode::Decrypt] {
                assert!(stream(c, &key, iv, side, &bytes(17, 13), &[5]).is_err());
            }
        }
    }

    #[test]
    fn test_stream_ciphers() {
        let key = bytes(32, 14);
        let nonce: [u8; 16] = bytes(16, 15).try_into().unwrap();
        let data = bytes(300, 16);

        let mut expected = data.clone();
        verified_garbage::chacha20::ChaCha20::new(&key.clone().try_into().unwrap(), &nonce)
            .apply_keystream(&mut expected);
        check(
            cipher(Algorithm::ChaCha20, CipherMode::Stream),
            &key,
            Some(&nonce),
            &data,
            &expected,
        );

        let mut expected = data.clone();
        verified_garbage::rc4::Rc4::new(&key[..16])
            .unwrap()
            .apply_keystream(&mut expected);
        check(
            cipher(Algorithm::Rc4, CipherMode::Stream),
            &key[..16],
            None,
            &data,
            &expected,
        );
    }

    #[test]
    fn test_reset_nonce() {
        let key = bytes(16, 17);
        let iv = bytes(16, 18);
        let other = bytes(16, 19);
        let data = bytes(40, 20);
        let c = cipher(Algorithm::Aes, CipherMode::Ctr);
        let mut e = Engine::new(c, &key, Some(&iv), Mode::Encrypt).unwrap_or_else(|_| panic!());
        let mut buf = vec![0; 40];
        // Leave a partial block pending, then restart with another nonce.
        e.update(&data[..5], &mut buf).unwrap_or_else(|_| panic!());
        match &mut e {
            Engine::Segments { mode, pending, .. } => {
                mode.reset(&other);
                pending.clear();
            }
            _ => unreachable!(),
        }
        e.update(&data, &mut buf).unwrap_or_else(|_| panic!());
        let expected = stream(c, &key, Some(&other), Mode::Encrypt, &data, &[40]).unwrap();
        assert_eq!(buf, expected);
    }

    #[test]
    fn test_xts() {
        let key = bytes(64, 21);
        let tweak = bytes(16, 22);
        let data = bytes(37, 23);
        let mut expected = data.clone();
        verified_garbage::aes_xts::AesXts::new(&key)
            .unwrap()
            .encrypt(&tweak.clone().try_into().unwrap(), &mut expected)
            .unwrap();
        let c = cipher(Algorithm::Aes, CipherMode::Xts);
        // Each update is a data unit.
        assert_eq!(
            stream(c, &key, Some(&tweak), Mode::Encrypt, &data, &[37]).unwrap(),
            expected
        );
        assert_eq!(
            stream(c, &key, Some(&tweak), Mode::Decrypt, &expected, &[37]).unwrap(),
            data
        );
        let mut e = Engine::new(c, &key, Some(&tweak), Mode::Encrypt).unwrap_or_else(|_| panic!());
        assert!(e.update(&data[..15], &mut [0; 15]).is_err());
        // Equal key halves are rejected.
        let mut same = key[..32].to_vec();
        same.extend_from_slice(&key[..32]);
        assert!(Engine::new(c, &same, Some(&tweak), Mode::Encrypt).is_err());
    }

    #[test]
    fn test_gcm() {
        let key = bytes(16, 24);
        let nonce = bytes(12, 25);
        let aad = bytes(20, 26);
        let data = bytes(100, 27);
        let gcm = verified_garbage::aes_gcm::AesGcm::new(&key).unwrap();
        let mut expected = data.clone();
        let tag = gcm.encrypt_in_place(&nonce, &aad, &mut expected).unwrap();

        let c = cipher(Algorithm::Aes, CipherMode::Gcm);
        for chunks in CHUNKINGS {
            let mut e =
                Engine::new(c, &key, Some(&nonce), Mode::Encrypt).unwrap_or_else(|_| panic!());
            e.update_aad(&aad[..3]).unwrap_or_else(|_| panic!());
            e.update_aad(&aad[3..]).unwrap_or_else(|_| panic!());
            let mut out = Vec::new();
            for piece in data.chunks(chunks[0]) {
                let mut buf = vec![0; piece.len()];
                e.update(piece, &mut buf).unwrap_or_else(|_| panic!());
                out.extend_from_slice(&buf);
            }
            e.finalize().unwrap();
            assert_eq!(out, expected);
            match &e {
                Engine::GcmEncrypt { tag: Some(t), .. } => assert_eq!(t, &tag),
                _ => unreachable!(),
            }

            for tag_len in [4, 8, 12, 13, 14, 15, 16] {
                for good in [true, false] {
                    let mut t = tag[..tag_len].to_vec();
                    if !good {
                        t[tag_len - 1] ^= 1;
                    }
                    let mut e = Engine::new(c, &key, Some(&nonce), Mode::Decrypt)
                        .unwrap_or_else(|_| panic!());
                    match &mut e {
                        Engine::GcmDecrypt { tag, .. } => *tag = Some(t),
                        _ => unreachable!(),
                    }
                    e.update_aad(&aad).unwrap_or_else(|_| panic!());
                    let mut out = Vec::new();
                    for piece in expected.chunks(chunks[0]) {
                        let mut buf = vec![0; piece.len()];
                        e.update(piece, &mut buf).unwrap_or_else(|_| panic!());
                        out.extend_from_slice(&buf);
                    }
                    assert_eq!(out, data);
                    assert_eq!(e.finalize().is_ok(), good);
                }
            }
        }
    }
}
