// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

// Implementation of the C2SP chunked-encryption specification
// (https://c2sp.org/chunked-encryption), instantiated with SHA-256 and
// AES-128-GCM.

use crate::buf::{CffiBuf, CffiMutBuf};
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

const CHUNK_SIZE: usize = 16 * 1024;
const SALT_LEN: usize = 24;
const COMMITMENT_LEN: usize = 32;
const HEADER_LEN: usize = SALT_LEN + COMMITMENT_LEN;
// The chunk counter is a 38-bit big-endian integer, limiting messages to
// 4 PiB - 1.
const MAX_CHUNK_COUNT: u64 = 1 << 38;
const INFO_PREFIX: &[u8] = b"c2sp.org/chunked-encryption@v1+";

// The scheme requires an AEAD nonce of at least 96 bits, and every AEAD we
// might instantiate it with (AES-GCM, ChaCha20-Poly1305) uses exactly 96.
const NONCE_LEN: usize = 12;

struct AeadParams {
    // Name from the IANA AEAD Algorithms registry, used in the HKDF info.
    iana_name: &'static [u8],
    key_len: usize,
    tag_len: usize,
    cipher: fn() -> &'static openssl::cipher::CipherRef,
}

impl AeadParams {
    fn wire_chunk_size(&self) -> usize {
        CHUNK_SIZE + self.tag_len
    }
}

static AES_128_GCM: AeadParams = AeadParams {
    iana_name: b"AEAD_AES_128_GCM",
    key_len: 16,
    tag_len: 16,
    cipher: openssl::cipher::Cipher::aes_128_gcm,
};

fn message_too_large_error() -> CryptographyError {
    CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
        "Message exceeds the maximum chunked encryption length (2**38 chunks).",
    ))
}

// HKDF-Expand (RFC 5869) with SHA-256, with the info supplied as
// concatenated parts.
fn hkdf_expand_sha256(prk: &[u8], info_parts: &[&[u8]], out: &mut [u8]) -> CryptographyResult<()> {
    let md = openssl::hash::MessageDigest::sha256();
    let mut previous: Option<cryptography_openssl::hmac::DigestBytes> = None;
    for (i, block) in out.chunks_mut(md.size()).enumerate() {
        let mut h = cryptography_openssl::hmac::Hmac::new(prk, md)?;
        if let Some(prev) = &previous {
            h.update(prev)?;
        }
        for part in info_parts {
            h.update(part)?;
        }
        h.update(&[(i + 1) as u8])?;
        let t = h.finish()?;
        block.copy_from_slice(&t[..block.len()]);
        previous = Some(t);
    }
    Ok(())
}

struct DerivedKeys {
    key: Vec<u8>,
    base_nonce: [u8; NONCE_LEN],
    commitment: [u8; COMMITMENT_LEN],
}

fn derive_keys(
    params: &AeadParams,
    input_key: &[u8],
    salt: &[u8],
    context: &[u8],
) -> CryptographyResult<DerivedKeys> {
    let mut out = vec![0; params.key_len + NONCE_LEN + COMMITMENT_LEN];
    hkdf_expand_sha256(
        input_key,
        &[INFO_PREFIX, params.iana_name, &[0x00], salt, context],
        &mut out,
    )?;
    let mut base_nonce = [0; NONCE_LEN];
    base_nonce.copy_from_slice(&out[params.key_len..params.key_len + NONCE_LEN]);
    let mut commitment = [0; COMMITMENT_LEN];
    commitment.copy_from_slice(&out[params.key_len + NONCE_LEN..]);
    out.truncate(params.key_len);
    Ok(DerivedKeys {
        key: out,
        base_nonce,
        commitment,
    })
}

// A single-message AEAD context that encrypts or decrypts successive chunks
// with the base nonce XOR'd with a chunk counter.
struct ChunkCipher {
    ctx: openssl::cipher_ctx::CipherCtx,
    base_nonce: [u8; NONCE_LEN],
    tag_len: usize,
    counter: u64,
}

impl ChunkCipher {
    fn new(params: &AeadParams, keys: &DerivedKeys, encrypt: bool) -> CryptographyResult<Self> {
        let mut ctx = openssl::cipher_ctx::CipherCtx::new()?;
        let cipher = (params.cipher)();
        if encrypt {
            ctx.encrypt_init(Some(cipher), Some(&keys.key), None)?;
        } else {
            ctx.decrypt_init(Some(cipher), Some(&keys.key), None)?;
        }
        ctx.set_iv_length(NONCE_LEN)?;
        Ok(ChunkCipher {
            ctx,
            base_nonce: keys.base_nonce,
            tag_len: params.tag_len,
            counter: 0,
        })
    }

    fn remaining_chunks(&self) -> u64 {
        MAX_CHUNK_COUNT - self.counter
    }

    fn next_nonce(&self) -> CryptographyResult<[u8; NONCE_LEN]> {
        if self.counter >= MAX_CHUNK_COUNT {
            return Err(message_too_large_error());
        }
        let mut nonce = self.base_nonce;
        for (n, c) in nonce[NONCE_LEN - 8..]
            .iter_mut()
            .zip(self.counter.to_be_bytes())
        {
            *n ^= c;
        }
        Ok(nonce)
    }

    // `out` must be exactly `plaintext.len() + self.tag_len` bytes.
    fn encrypt_chunk(&mut self, plaintext: &[u8], out: &mut [u8]) -> CryptographyResult<()> {
        let nonce = self.next_nonce()?;
        self.ctx.encrypt_init(None, None, Some(&nonce))?;
        let (ciphertext, tag) = out.split_at_mut(plaintext.len());
        let n = self.ctx.cipher_update(plaintext, Some(ciphertext))?;
        assert_eq!(n, plaintext.len());
        let mut final_block = [0];
        let n = self.ctx.cipher_final(&mut final_block)?;
        assert_eq!(n, 0);
        self.ctx.tag(tag)?;
        self.counter += 1;
        Ok(())
    }

    // `ciphertext` includes the trailing tag; `out` must be exactly
    // `ciphertext.len() - self.tag_len` bytes.
    fn decrypt_chunk(&mut self, ciphertext: &[u8], out: &mut [u8]) -> CryptographyResult<()> {
        let nonce = self.next_nonce()?;
        let (data, tag) = ciphertext.split_at(ciphertext.len() - self.tag_len);
        self.ctx.decrypt_init(None, None, Some(&nonce))?;
        self.ctx.set_tag(tag)?;
        let n = self
            .ctx
            .cipher_update(data, Some(out))
            .map_err(|_| exceptions::InvalidTag::new_err(()))?;
        assert_eq!(n, data.len());
        let mut final_block = [0];
        self.ctx
            .cipher_final(&mut final_block)
            .map_err(|_| exceptions::InvalidTag::new_err(()))?;
        self.counter += 1;
        Ok(())
    }
}

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.chunked_encryption")]
pub(crate) struct Encrypter {
    cipher: ChunkCipher,
    buffer: Vec<u8>,
    header: [u8; HEADER_LEN],
    header_pending: bool,
    finalized: bool,
    errored: bool,
}

impl Encrypter {
    fn check_active(&self) -> CryptographyResult<()> {
        if self.errored {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("Context cannot be used after an error."),
            ));
        }
        if self.finalized {
            return Err(exceptions::already_finalized_error());
        }
        Ok(())
    }

    fn update_out_len(&self, data_len: usize) -> usize {
        let n_chunks = (self.buffer.len() + data_len) / CHUNK_SIZE;
        let header = if self.header_pending { HEADER_LEN } else { 0 };
        header + n_chunks * (CHUNK_SIZE + self.cipher.tag_len)
    }

    fn update_impl(&mut self, mut data: &[u8], out: &mut [u8]) -> CryptographyResult<usize> {
        // Check the chunk counter limit up front so that the error doesn't
        // leave a partially written output behind.
        let n_chunks = ((self.buffer.len() + data.len()) / CHUNK_SIZE) as u64;
        if n_chunks > self.cipher.remaining_chunks() {
            return Err(message_too_large_error());
        }

        let wire_chunk = CHUNK_SIZE + self.cipher.tag_len;
        let mut written = 0;
        if self.header_pending {
            out[..HEADER_LEN].copy_from_slice(&self.header);
            written += HEADER_LEN;
            self.header_pending = false;
        }
        if !self.buffer.is_empty() {
            let take = std::cmp::min(CHUNK_SIZE - self.buffer.len(), data.len());
            self.buffer.extend_from_slice(&data[..take]);
            data = &data[take..];
            if self.buffer.len() == CHUNK_SIZE {
                self.cipher
                    .encrypt_chunk(&self.buffer, &mut out[written..written + wire_chunk])?;
                written += wire_chunk;
                self.buffer.clear();
            }
        }
        while data.len() >= CHUNK_SIZE {
            let (chunk, rest) = data.split_at(CHUNK_SIZE);
            self.cipher
                .encrypt_chunk(chunk, &mut out[written..written + wire_chunk])?;
            written += wire_chunk;
            data = rest;
        }
        self.buffer.extend_from_slice(data);
        Ok(written)
    }
}

#[pyo3::pymethods]
impl Encrypter {
    #[new]
    fn new(key: CffiBuf<'_>, context: CffiBuf<'_>) -> CryptographyResult<Self> {
        let params = &AES_128_GCM;
        if key.as_bytes().len() != params.key_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("key must be 16 bytes."),
            ));
        }
        let mut salt = [0; SALT_LEN];
        cryptography_openssl::rand::rand_bytes(&mut salt)?;
        let keys = derive_keys(params, key.as_bytes(), &salt, context.as_bytes())?;
        let cipher = ChunkCipher::new(params, &keys, true)?;
        let mut header = [0; HEADER_LEN];
        header[..SALT_LEN].copy_from_slice(&salt);
        header[SALT_LEN..].copy_from_slice(&keys.commitment);
        Ok(Encrypter {
            cipher,
            buffer: Vec::with_capacity(CHUNK_SIZE),
            header,
            header_pending: true,
            finalized: false,
            errored: false,
        })
    }

    #[staticmethod]
    fn generate_key(
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<pyo3::Bound<'_, pyo3::types::PyBytes>> {
        crate::backend::rand::get_rand_bytes(py, AES_128_GCM.key_len)
    }

    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.check_active()?;
        let data = data.as_bytes();
        let out_len = self.update_out_len(data.len());
        let result = pyo3::types::PyBytes::new_with(py, out_len, |b| {
            let n = self.update_impl(data, b)?;
            debug_assert_eq!(n, out_len);
            Ok(())
        });
        if result.is_err() {
            self.errored = true;
        }
        Ok(result?)
    }

    fn update_into(
        &mut self,
        data: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.check_active()?;
        let data = data.as_bytes();
        let out_len = self.update_out_len(data.len());
        let out = buf.as_mut_bytes();
        if out.len() < out_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be at least {out_len} bytes"
                )),
            ));
        }
        let result = self.update_impl(data, out);
        if result.is_err() {
            self.errored = true;
        }
        result
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.check_active()?;
        let header = if self.header_pending { HEADER_LEN } else { 0 };
        let out_len = header + self.buffer.len() + self.cipher.tag_len;
        let result = pyo3::types::PyBytes::new_with(py, out_len, |b| {
            if header != 0 {
                b[..HEADER_LEN].copy_from_slice(&self.header);
            }
            self.cipher.encrypt_chunk(&self.buffer, &mut b[header..])?;
            Ok(())
        });
        match result {
            Ok(ciphertext) => {
                self.header_pending = false;
                self.buffer.clear();
                self.finalized = true;
                Ok(ciphertext)
            }
            Err(e) => {
                self.errored = true;
                Err(e.into())
            }
        }
    }
}

enum DecrypterState {
    // Buffering the salt and commitment; `key` and `context` are retained
    // until they arrive and the keys can be derived.
    Header {
        key: Vec<u8>,
        context: Vec<u8>,
        buf: Vec<u8>,
    },
    Body {
        cipher: ChunkCipher,
        buffer: Vec<u8>,
    },
    Finalized,
    // A decryption error is permanent: no further data may be processed.
    Errored,
}

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.chunked_encryption")]
pub(crate) struct Decrypter {
    state: DecrypterState,
}

impl Decrypter {
    fn check_active(&self) -> CryptographyResult<()> {
        match self.state {
            DecrypterState::Header { .. } | DecrypterState::Body { .. } => Ok(()),
            DecrypterState::Finalized => Err(exceptions::already_finalized_error()),
            DecrypterState::Errored => {
                Err(CryptographyError::from(exceptions::InvalidTag::new_err(())))
            }
        }
    }

    fn update_out_len(&self, data_len: usize) -> usize {
        let wire_chunk = AES_128_GCM.wire_chunk_size();
        let body_len = match &self.state {
            DecrypterState::Header { buf, .. } => data_len.saturating_sub(HEADER_LEN - buf.len()),
            DecrypterState::Body { buffer, .. } => buffer.len() + data_len,
            DecrypterState::Finalized | DecrypterState::Errored => unreachable!(),
        };
        (body_len / wire_chunk) * CHUNK_SIZE
    }

    fn update_impl(&mut self, mut data: &[u8], out: &mut [u8]) -> CryptographyResult<usize> {
        if let DecrypterState::Header { key, context, buf } = &mut self.state {
            let take = std::cmp::min(HEADER_LEN - buf.len(), data.len());
            buf.extend_from_slice(&data[..take]);
            data = &data[take..];
            if buf.len() < HEADER_LEN {
                debug_assert!(data.is_empty());
                return Ok(0);
            }
            let (salt, commitment) = buf.split_at(SALT_LEN);
            let keys = derive_keys(&AES_128_GCM, key, salt, context)?;
            if !openssl::memcmp::eq(&keys.commitment, commitment) {
                return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
            }
            let cipher = ChunkCipher::new(&AES_128_GCM, &keys, false)?;
            self.state = DecrypterState::Body {
                cipher,
                buffer: Vec::with_capacity(AES_128_GCM.wire_chunk_size()),
            };
        }
        let DecrypterState::Body { cipher, buffer } = &mut self.state else {
            unreachable!()
        };

        let wire_chunk = CHUNK_SIZE + cipher.tag_len;
        // Check the chunk counter limit up front so that the error doesn't
        // leave a partially written output behind.
        let n_chunks = ((buffer.len() + data.len()) / wire_chunk) as u64;
        if n_chunks > cipher.remaining_chunks() {
            return Err(message_too_large_error());
        }

        // Any complete wire chunk is necessarily not the final chunk (the
        // final chunk is always shorter), so it can be decrypted, and its
        // plaintext released, as soon as it is available. If the ciphertext
        // ends on a chunk boundary, the missing final chunk is detected in
        // finalize().
        let mut written = 0;
        if !buffer.is_empty() {
            let take = std::cmp::min(wire_chunk - buffer.len(), data.len());
            buffer.extend_from_slice(&data[..take]);
            data = &data[take..];
            if buffer.len() == wire_chunk {
                cipher.decrypt_chunk(buffer, &mut out[written..written + CHUNK_SIZE])?;
                written += CHUNK_SIZE;
                buffer.clear();
            }
        }
        while data.len() >= wire_chunk {
            let (chunk, rest) = data.split_at(wire_chunk);
            cipher.decrypt_chunk(chunk, &mut out[written..written + CHUNK_SIZE])?;
            written += CHUNK_SIZE;
            data = rest;
        }
        buffer.extend_from_slice(data);
        Ok(written)
    }
}

#[pyo3::pymethods]
impl Decrypter {
    #[new]
    fn new(key: CffiBuf<'_>, context: CffiBuf<'_>) -> CryptographyResult<Self> {
        if key.as_bytes().len() != AES_128_GCM.key_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err("key must be 16 bytes."),
            ));
        }
        Ok(Decrypter {
            state: DecrypterState::Header {
                key: key.as_bytes().to_vec(),
                context: context.as_bytes().to_vec(),
                buf: Vec::with_capacity(HEADER_LEN),
            },
        })
    }

    #[staticmethod]
    fn generate_key(
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<pyo3::Bound<'_, pyo3::types::PyBytes>> {
        crate::backend::rand::get_rand_bytes(py, AES_128_GCM.key_len)
    }

    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.check_active()?;
        let data = data.as_bytes();
        let out_len = self.update_out_len(data.len());
        let result = pyo3::types::PyBytes::new_with(py, out_len, |b| {
            let n = self.update_impl(data, b)?;
            debug_assert_eq!(n, out_len);
            Ok(())
        });
        if result.is_err() {
            self.state = DecrypterState::Errored;
        }
        Ok(result?)
    }

    fn update_into(
        &mut self,
        data: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.check_active()?;
        let data = data.as_bytes();
        let out_len = self.update_out_len(data.len());
        let out = buf.as_mut_bytes();
        if out.len() < out_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be at least {out_len} bytes"
                )),
            ));
        }
        let result = self.update_impl(data, out);
        if result.is_err() {
            self.state = DecrypterState::Errored;
        }
        result
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.check_active()?;
        let result = match &mut self.state {
            // The full salt and commitment never arrived: the message is
            // truncated.
            DecrypterState::Header { .. } => {
                Err(CryptographyError::from(exceptions::InvalidTag::new_err(())))
            }
            DecrypterState::Body { cipher, buffer } => {
                if buffer.len() < cipher.tag_len {
                    // The final chunk is missing (the ciphertext ended
                    // exactly on a chunk boundary) or is too short to be
                    // valid: the message is truncated.
                    Err(CryptographyError::from(exceptions::InvalidTag::new_err(())))
                } else {
                    // buffer is always shorter than a wire chunk, so the
                    // final chunk's plaintext is necessarily shorter than
                    // CHUNK_SIZE, as the specification requires.
                    let out_len = buffer.len() - cipher.tag_len;
                    pyo3::types::PyBytes::new_with(py, out_len, |b| {
                        cipher.decrypt_chunk(buffer, b)?;
                        Ok(())
                    })
                    .map_err(CryptographyError::from)
                }
            }
            DecrypterState::Finalized | DecrypterState::Errored => unreachable!(),
        };
        match result {
            Ok(plaintext) => {
                self.state = DecrypterState::Finalized;
                Ok(plaintext)
            }
            Err(e) => {
                self.state = DecrypterState::Errored;
                Err(e)
            }
        }
    }
}

#[pyo3::pymodule(gil_used = false)]
#[pyo3(name = "chunked_encryption")]
pub(crate) mod chunked_encryption_mod {
    #[pymodule_export]
    use super::{Decrypter, Encrypter};
}
