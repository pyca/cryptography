// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

// Implementation of the C2SP chunked-encryption specification
// (https://c2sp.org/chunked-encryption), providing its two named
// instantiations: Cobblestone-128 (SHA-512 and AES-128-GCM) and
// Cobblestone-256 (SHA-512 and AES-256-GCM).

use pyo3::types::{PyAnyMethods, PyBytesMethods};

use crate::backend::aead::AesGcm;
use crate::backend::kdf::HkdfExpand;
use crate::buf::{CffiBuf, CffiMutBuf};
use crate::error::{CryptographyError, CryptographyResult};
use crate::{exceptions, types};

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
};

static AES_256_GCM: AeadParams = AeadParams {
    iana_name: b"AEAD_AES_256_GCM",
    key_len: 32,
    tag_len: 16,
};

fn message_too_large_error() -> CryptographyError {
    CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
        "Message exceeds the maximum chunked encryption length (2**38 chunks).",
    ))
}

fn check_key_length(params: &AeadParams, key: &[u8]) -> CryptographyResult<()> {
    if key.len() != params.key_len {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(format!(
                "key must be {} bytes.",
                params.key_len
            )),
        ));
    }
    Ok(())
}

fn mixing_error() -> CryptographyError {
    CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
        "A Cobblestone decryptor cannot be used for both streaming \
         (update/finalize) and random-access (decrypt_range) decryption.",
    ))
}

fn truncated_error() -> CryptographyError {
    CryptographyError::from(exceptions::InvalidTag::new_err(()))
}

// Reads up to `want` bytes starting at byte `pos` from a random-access
// ciphertext source. When `buffer` is `Some`, the source is a buffer-protocol
// object and is indexed directly; otherwise it is a binary file-like object and
// is read via seek()/read(). Fewer than `want` bytes are returned only at the
// end of the source.
fn read_at(
    py: pyo3::Python<'_>,
    source: &pyo3::Bound<'_, pyo3::PyAny>,
    buffer: Option<&CffiBuf<'_>>,
    pos: u64,
    want: usize,
) -> CryptographyResult<Vec<u8>> {
    if let Some(buf) = buffer {
        let bytes = buf.as_bytes();
        let start = std::cmp::min(pos, bytes.len() as u64) as usize;
        let end = std::cmp::min(start.saturating_add(want), bytes.len());
        return Ok(bytes[start..end].to_vec());
    }

    source.call_method1(pyo3::intern!(py, "seek"), (pos,))?;
    let mut out = Vec::with_capacity(want);
    while out.len() < want {
        let chunk = source.call_method1(pyo3::intern!(py, "read"), (want - out.len(),))?;
        // A non-blocking stream may return None to signal "no data available";
        // treat it, like an empty read, as the end of the input.
        if chunk.is_none() {
            break;
        }
        let read = chunk.extract::<CffiBuf<'_>>()?;
        let read_bytes = read.as_bytes();
        if read_bytes.is_empty() {
            break;
        }
        let take = std::cmp::min(read_bytes.len(), want - out.len());
        out.extend_from_slice(&read_bytes[..take]);
    }
    Ok(out)
}

struct DerivedKeys<'p> {
    key: pyo3::Bound<'p, pyo3::types::PyBytes>,
    base_nonce: [u8; NONCE_LEN],
    commitment: [u8; COMMITMENT_LEN],
}

fn derive_keys<'p>(
    py: pyo3::Python<'p>,
    params: &AeadParams,
    input_key: &[u8],
    salt: &[u8],
    context: &[u8],
) -> CryptographyResult<DerivedKeys<'p>> {
    let mut info = Vec::with_capacity(
        INFO_PREFIX.len() + params.iana_name.len() + 1 + salt.len() + context.len(),
    );
    info.extend_from_slice(INFO_PREFIX);
    info.extend_from_slice(params.iana_name);
    info.push(0x00);
    info.extend_from_slice(salt);
    info.extend_from_slice(context);

    let algorithm = types::SHA512.get(py)?.call0()?;
    let mut hkdf = HkdfExpand::new(
        py,
        algorithm.unbind(),
        params.key_len + NONCE_LEN + COMMITMENT_LEN,
        Some(pyo3::types::PyBytes::new(py, &info).unbind()),
        None,
    )?;
    let okm = hkdf.derive(py, CffiBuf::from_bytes(py, input_key))?;
    let okm_bytes = okm.as_bytes();

    let key = pyo3::types::PyBytes::new(py, &okm_bytes[..params.key_len]);
    let mut base_nonce = [0; NONCE_LEN];
    base_nonce.copy_from_slice(&okm_bytes[params.key_len..params.key_len + NONCE_LEN]);
    let mut commitment = [0; COMMITMENT_LEN];
    commitment.copy_from_slice(&okm_bytes[params.key_len + NONCE_LEN..]);
    Ok(DerivedKeys {
        key,
        base_nonce,
        commitment,
    })
}

// The per-chunk nonce sequence: the base nonce XOR'd with an incrementing
// chunk counter.
struct ChunkNonces {
    base_nonce: [u8; NONCE_LEN],
    counter: u64,
}

impl ChunkNonces {
    fn check_capacity(&self, n_chunks: u64) -> CryptographyResult<()> {
        if n_chunks > MAX_CHUNK_COUNT - self.counter {
            return Err(message_too_large_error());
        }
        Ok(())
    }

    // The nonce for an arbitrary chunk index: the base nonce XOR'd with the
    // index as a big-endian integer. This is stateless, so it serves both the
    // sequential streaming path (via `next`) and random-access decryption.
    fn nonce_for(&self, index: u64) -> CryptographyResult<[u8; NONCE_LEN]> {
        if index >= MAX_CHUNK_COUNT {
            return Err(message_too_large_error());
        }
        let mut nonce = self.base_nonce;
        for (n, c) in nonce[NONCE_LEN - 8..].iter_mut().zip(index.to_be_bytes()) {
            *n ^= c;
        }
        Ok(nonce)
    }

    fn next(&mut self) -> CryptographyResult<[u8; NONCE_LEN]> {
        let nonce = self.nonce_for(self.counter)?;
        self.counter += 1;
        Ok(nonce)
    }
}

// A single-message AEAD context that encrypts or decrypts successive chunks.
struct ChunkCipher {
    aead: AesGcm,
    nonces: ChunkNonces,
    tag_len: usize,
}

impl ChunkCipher {
    fn new(
        py: pyo3::Python<'_>,
        params: &AeadParams,
        keys: &DerivedKeys<'_>,
    ) -> CryptographyResult<Self> {
        let aead = AesGcm::new(py, keys.key.clone().unbind().into_any())?;
        Ok(ChunkCipher {
            aead,
            nonces: ChunkNonces {
                base_nonce: keys.base_nonce,
                counter: 0,
            },
            tag_len: params.tag_len,
        })
    }

    // `out` must be exactly `plaintext.len() + self.tag_len` bytes.
    fn encrypt_chunk(
        &mut self,
        py: pyo3::Python<'_>,
        plaintext: &[u8],
        out: &mut [u8],
    ) -> CryptographyResult<()> {
        let nonce = self.nonces.next()?;
        self.aead.encrypt_into(
            py,
            CffiBuf::from_bytes(py, &nonce),
            CffiBuf::from_bytes(py, plaintext),
            None,
            CffiMutBuf::from_bytes(py, out),
        )?;
        Ok(())
    }

    // `ciphertext` includes the trailing tag; `out` must be exactly
    // `ciphertext.len() - self.tag_len` bytes.
    fn decrypt_chunk(
        &mut self,
        py: pyo3::Python<'_>,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> CryptographyResult<()> {
        let nonce = self.nonces.next()?;
        self.aead.decrypt_into(
            py,
            CffiBuf::from_bytes(py, &nonce),
            CffiBuf::from_bytes(py, ciphertext),
            None,
            CffiMutBuf::from_bytes(py, out),
        )?;
        Ok(())
    }

    // Decrypts the chunk at an explicit `index`, without advancing the
    // sequential counter, for random-access decryption. `ciphertext` includes
    // the trailing tag; `out` must be exactly `ciphertext.len() - self.tag_len`
    // bytes. Returns InvalidTag if the chunk does not authenticate (e.g. it was
    // tampered with, or belongs at a different index).
    fn decrypt_chunk_at(
        &self,
        py: pyo3::Python<'_>,
        index: u64,
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> CryptographyResult<()> {
        let nonce = self.nonces.nonce_for(index)?;
        self.aead.decrypt_into(
            py,
            CffiBuf::from_bytes(py, &nonce),
            CffiBuf::from_bytes(py, ciphertext),
            None,
            CffiMutBuf::from_bytes(py, out),
        )?;
        Ok(())
    }
}

struct ChunkedEncryptor {
    cipher: ChunkCipher,
    buffer: Vec<u8>,
    header: [u8; HEADER_LEN],
    header_pending: bool,
    finalized: bool,
}

impl ChunkedEncryptor {
    fn new(
        py: pyo3::Python<'_>,
        params: &AeadParams,
        key: &[u8],
        context: &[u8],
    ) -> CryptographyResult<Self> {
        check_key_length(params, key)?;
        let mut salt = [0; SALT_LEN];
        cryptography_openssl::rand::rand_bytes(&mut salt)?;
        let keys = derive_keys(py, params, key, &salt, context)?;
        let cipher = ChunkCipher::new(py, params, &keys)?;
        let mut header = [0; HEADER_LEN];
        header[..SALT_LEN].copy_from_slice(&salt);
        header[SALT_LEN..].copy_from_slice(&keys.commitment);
        Ok(ChunkedEncryptor {
            cipher,
            buffer: Vec::with_capacity(CHUNK_SIZE),
            header,
            header_pending: true,
            finalized: false,
        })
    }

    fn check_active(&self) -> CryptographyResult<()> {
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

    // `out` must be at least `self.update_out_len(data.len())` bytes; both
    // callers check this before any state is modified, so the header and
    // every chunk written below are guaranteed to fit.
    fn update_impl(
        &mut self,
        py: pyo3::Python<'_>,
        mut data: &[u8],
        out: &mut [u8],
    ) -> CryptographyResult<usize> {
        // Check the chunk counter limit up front so that the error doesn't
        // leave a partially written output behind.
        let n_chunks = ((self.buffer.len() + data.len()) / CHUNK_SIZE) as u64;
        self.cipher.nonces.check_capacity(n_chunks)?;

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
                self.cipher.encrypt_chunk(
                    py,
                    &self.buffer,
                    &mut out[written..written + wire_chunk],
                )?;
                written += wire_chunk;
                self.buffer.clear();
            }
        }
        while data.len() >= CHUNK_SIZE {
            let (chunk, rest) = data.split_at(CHUNK_SIZE);
            self.cipher
                .encrypt_chunk(py, chunk, &mut out[written..written + wire_chunk])?;
            written += wire_chunk;
            data = rest;
        }
        self.buffer.extend_from_slice(data);
        Ok(written)
    }

    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        data: &[u8],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.check_active()?;
        let out_len = self.update_out_len(data.len());
        Ok(pyo3::types::PyBytes::new_with(py, out_len, |b| {
            let n = self.update_impl(py, data, b)?;
            debug_assert_eq!(n, out_len);
            Ok(())
        })?)
    }

    fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        data: &[u8],
        out: &mut [u8],
    ) -> CryptographyResult<usize> {
        self.check_active()?;
        let out_len = self.update_out_len(data.len());
        if out.len() < out_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be at least {out_len} bytes"
                )),
            ));
        }
        self.update_impl(py, data, out)
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.check_active()?;
        self.finalized = true;
        let header = if self.header_pending { HEADER_LEN } else { 0 };
        let out_len = header + self.buffer.len() + self.cipher.tag_len;
        let result = pyo3::types::PyBytes::new_with(py, out_len, |b| {
            if header != 0 {
                b[..HEADER_LEN].copy_from_slice(&self.header);
            }
            self.cipher
                .encrypt_chunk(py, &self.buffer, &mut b[header..])?;
            Ok(())
        })?;
        self.buffer.clear();
        Ok(result)
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
}

struct ChunkedDecryptor {
    params: &'static AeadParams,
    // `None` once finalized, or after any error: a failed context cannot
    // process more data.
    state: Option<DecrypterState>,
    // Retained for random-access decryption (`decrypt_range`), which derives
    // keys from a header it reads directly from the ciphertext source rather
    // than from the streamed input.
    key: Vec<u8>,
    context: Vec<u8>,
    // The seek cipher, derived and commitment-verified on the first
    // `decrypt_range` call and reused for subsequent ranges.
    seek_cipher: Option<ChunkCipher>,
    // Streaming (`update`/`finalize`) and random-access (`decrypt_range`)
    // decryption are mutually exclusive on a single instance.
    streaming_used: bool,
    seeking_used: bool,
}

impl ChunkedDecryptor {
    fn new(params: &'static AeadParams, key: &[u8], context: &[u8]) -> CryptographyResult<Self> {
        check_key_length(params, key)?;
        Ok(ChunkedDecryptor {
            params,
            state: Some(DecrypterState::Header {
                key: key.to_vec(),
                context: context.to_vec(),
                buf: Vec::with_capacity(HEADER_LEN),
            }),
            key: key.to_vec(),
            context: context.to_vec(),
            seek_cipher: None,
            streaming_used: false,
            seeking_used: false,
        })
    }

    fn active_state(&mut self) -> CryptographyResult<&mut DecrypterState> {
        match &mut self.state {
            Some(state) => Ok(state),
            None => Err(exceptions::already_finalized_error()),
        }
    }

    fn update_out_len(params: &AeadParams, state: &DecrypterState, data_len: usize) -> usize {
        let body_len = match state {
            DecrypterState::Header { buf, .. } => data_len.saturating_sub(HEADER_LEN - buf.len()),
            DecrypterState::Body { buffer, .. } => buffer.len() + data_len,
        };
        (body_len / params.wire_chunk_size()) * CHUNK_SIZE
    }

    fn update_impl(
        py: pyo3::Python<'_>,
        params: &AeadParams,
        state: &mut DecrypterState,
        mut data: &[u8],
        out: &mut [u8],
    ) -> CryptographyResult<usize> {
        match state {
            DecrypterState::Header { key, context, buf } => {
                let take = std::cmp::min(HEADER_LEN - buf.len(), data.len());
                buf.extend_from_slice(&data[..take]);
                data = &data[take..];
                if buf.len() < HEADER_LEN {
                    debug_assert!(data.is_empty());
                    return Ok(0);
                }
                let (salt, commitment) = buf.split_at(SALT_LEN);
                let keys = derive_keys(py, params, key, salt, context)?;
                if !cryptography_crypto::constant_time::bytes_eq(&keys.commitment, commitment) {
                    return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
                }
                let mut cipher = ChunkCipher::new(py, params, &keys)?;
                let mut buffer = Vec::with_capacity(params.wire_chunk_size());
                let written = Self::decrypt_chunks(py, &mut cipher, &mut buffer, data, out)?;
                *state = DecrypterState::Body { cipher, buffer };
                Ok(written)
            }
            DecrypterState::Body { cipher, buffer } => {
                Self::decrypt_chunks(py, cipher, buffer, data, out)
            }
        }
    }

    fn decrypt_chunks(
        py: pyo3::Python<'_>,
        cipher: &mut ChunkCipher,
        buffer: &mut Vec<u8>,
        mut data: &[u8],
        out: &mut [u8],
    ) -> CryptographyResult<usize> {
        let wire_chunk = CHUNK_SIZE + cipher.tag_len;
        // Check the chunk counter limit up front so that the error doesn't
        // leave a partially written output behind.
        let n_chunks = ((buffer.len() + data.len()) / wire_chunk) as u64;
        cipher.nonces.check_capacity(n_chunks)?;

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
                cipher.decrypt_chunk(py, buffer, &mut out[written..written + CHUNK_SIZE])?;
                written += CHUNK_SIZE;
                buffer.clear();
            }
        }
        while data.len() >= wire_chunk {
            let (chunk, rest) = data.split_at(wire_chunk);
            cipher.decrypt_chunk(py, chunk, &mut out[written..written + CHUNK_SIZE])?;
            written += CHUNK_SIZE;
            data = rest;
        }
        buffer.extend_from_slice(data);
        Ok(written)
    }

    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        data: &[u8],
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if self.seeking_used {
            return Err(mixing_error());
        }
        self.streaming_used = true;
        let params = self.params;
        let state = self.active_state()?;
        let out_len = Self::update_out_len(params, state, data.len());
        let result = pyo3::types::PyBytes::new_with(py, out_len, |b| {
            let n = Self::update_impl(py, params, state, data, b)?;
            debug_assert_eq!(n, out_len);
            Ok(())
        });
        if result.is_err() {
            self.state = None;
        }
        Ok(result?)
    }

    fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        data: &[u8],
        out: &mut [u8],
    ) -> CryptographyResult<usize> {
        if self.seeking_used {
            return Err(mixing_error());
        }
        self.streaming_used = true;
        let params = self.params;
        let state = self.active_state()?;
        let out_len = Self::update_out_len(params, state, data.len());
        if out.len() < out_len {
            return Err(CryptographyError::from(
                pyo3::exceptions::PyValueError::new_err(format!(
                    "buffer must be at least {out_len} bytes"
                )),
            ));
        }
        let result = Self::update_impl(py, params, state, data, out);
        if result.is_err() {
            self.state = None;
        }
        result
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if self.seeking_used {
            return Err(mixing_error());
        }
        self.streaming_used = true;
        // Whether it succeeds or fails, finalization consumes the state: no
        // further data may be processed.
        match self.state.take() {
            None => Err(exceptions::already_finalized_error()),
            // The full salt and commitment never arrived: the message is
            // truncated.
            Some(DecrypterState::Header { .. }) => {
                Err(CryptographyError::from(exceptions::InvalidTag::new_err(())))
            }
            Some(DecrypterState::Body { mut cipher, buffer }) => {
                if buffer.len() < cipher.tag_len {
                    // The final chunk is missing (the ciphertext ended
                    // exactly on a chunk boundary) or is too short to be
                    // valid: the message is truncated.
                    return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
                }
                // buffer is always shorter than a wire chunk, so the final
                // chunk's plaintext is necessarily shorter than CHUNK_SIZE,
                // as the specification requires.
                let out_len = buffer.len() - cipher.tag_len;
                Ok(pyo3::types::PyBytes::new_with(py, out_len, |b| {
                    cipher.decrypt_chunk(py, &buffer, b)?;
                    Ok(())
                })?)
            }
        }
    }

    // Random-access decryption. Returns the authenticated plaintext bytes in
    // `[offset, offset + length)`, reading only the ciphertext chunks that
    // cover that range from `source`.
    //
    // `source` is either a buffer-protocol object (e.g. bytes or an mmap) or a
    // binary file-like object exposing `seek(pos)` and `read(n)`. The requested
    // range is silently expanded to whole 16 KiB chunk boundaries so that every
    // chunk touched is authenticated by its AEAD tag; only after that check
    // passes is the requested sub-range sliced out and returned. Unauthenticated
    // bytes are never returned.
    //
    // Note: a range read authenticates the bytes it returns, but not the
    // message as a whole. It cannot detect truncation of chunks beyond the
    // requested range, so the total plaintext length must come from a trusted
    // source, not be inferred from the (possibly truncated) ciphertext.
    fn decrypt_range<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        source: &pyo3::Bound<'p, pyo3::PyAny>,
        offset: u64,
        length: usize,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        if self.streaming_used {
            return Err(mixing_error());
        }
        self.seeking_used = true;

        if length == 0 {
            return Ok(pyo3::types::PyBytes::new(py, &[]));
        }

        let params = self.params;
        let wire = params.wire_chunk_size();
        let first_chunk = offset / CHUNK_SIZE as u64;
        // Bound the range to the maximum message length (which also guards
        // against `offset + length` overflowing for a hostile offset). This
        // keeps every chunk index below MAX_CHUNK_COUNT.
        let last_byte = offset
            .checked_add(length as u64)
            .filter(|end| *end <= MAX_CHUNK_COUNT * CHUNK_SIZE as u64)
            .ok_or_else(message_too_large_error)?
            - 1;
        let last_chunk = last_byte / CHUNK_SIZE as u64;
        let n_chunks = (last_chunk - first_chunk + 1) as usize;

        // A buffer-protocol source (bytes, mmap, ...) is indexed directly; any
        // other object is treated as a seek()/read() file-like.
        let as_buffer = source.extract::<CffiBuf<'_>>().ok();

        // Derive the seek cipher (and verify the commitment) once, from the
        // 56-byte header at the front of the ciphertext.
        if self.seek_cipher.is_none() {
            let header = read_at(py, source, as_buffer.as_ref(), 0, HEADER_LEN)?;
            if header.len() < HEADER_LEN {
                return Err(truncated_error());
            }
            let (salt, commitment) = header.split_at(SALT_LEN);
            let keys = derive_keys(py, params, &self.key, salt, &self.context)?;
            if !cryptography_crypto::constant_time::bytes_eq(&keys.commitment, commitment) {
                return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
            }
            self.seek_cipher = Some(ChunkCipher::new(py, params, &keys)?);
        }
        let cipher = self.seek_cipher.as_ref().unwrap();

        // Read the contiguous ciphertext window covering the requested chunks in
        // a single read, so a multi-chunk range is one round trip to `source`.
        let ct_start = HEADER_LEN as u64 + first_chunk * wire as u64;
        let data = read_at(py, source, as_buffer.as_ref(), ct_start, n_chunks * wire)?;

        // Decrypt whole chunks, releasing plaintext only for those that
        // authenticate. Any trailing partial wire chunk is the message's short
        // final chunk.
        let mut plaintext = Vec::with_capacity(n_chunks * CHUNK_SIZE);
        let mut consumed = 0;
        let mut index = first_chunk;
        while consumed + wire <= data.len() {
            let start = plaintext.len();
            plaintext.resize(start + CHUNK_SIZE, 0);
            cipher.decrypt_chunk_at(
                py,
                index,
                &data[consumed..consumed + wire],
                &mut plaintext[start..],
            )?;
            consumed += wire;
            index += 1;
        }
        let remainder = data.len() - consumed;
        if remainder > 0 {
            if remainder < params.tag_len {
                // Too short to be a valid chunk: the message is truncated.
                return Err(truncated_error());
            }
            let start = plaintext.len();
            plaintext.resize(start + remainder - params.tag_len, 0);
            cipher.decrypt_chunk_at(py, index, &data[consumed..], &mut plaintext[start..])?;
        }

        // Slice out the requested range. If the authenticated plaintext does
        // not reach `offset + length`, the message is shorter than the request
        // (truncated, or the caller read past the end); either way we have no
        // authenticated bytes to return there.
        let intra = (offset - first_chunk * CHUNK_SIZE as u64) as usize;
        let end = intra + length;
        if end > plaintext.len() {
            return Err(truncated_error());
        }
        Ok(pyo3::types::PyBytes::new(py, &plaintext[intra..end]))
    }
}

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.cobblestone")]
pub(crate) struct Cobblestone128Encryptor {
    inner: ChunkedEncryptor,
}

#[pyo3::pymethods]
impl Cobblestone128Encryptor {
    #[new]
    fn new(
        py: pyo3::Python<'_>,
        key: CffiBuf<'_>,
        context: CffiBuf<'_>,
    ) -> CryptographyResult<Self> {
        Ok(Cobblestone128Encryptor {
            inner: ChunkedEncryptor::new(py, &AES_128_GCM, key.as_bytes(), context.as_bytes())?,
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
        self.inner.update(py, data.as_bytes())
    }

    fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        data: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.inner
            .update_into(py, data.as_bytes(), buf.as_mut_bytes())
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.inner.finalize(py)
    }
}

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.cobblestone")]
pub(crate) struct Cobblestone128Decryptor {
    inner: ChunkedDecryptor,
}

#[pyo3::pymethods]
impl Cobblestone128Decryptor {
    #[new]
    fn new(key: CffiBuf<'_>, context: CffiBuf<'_>) -> CryptographyResult<Self> {
        Ok(Cobblestone128Decryptor {
            inner: ChunkedDecryptor::new(&AES_128_GCM, key.as_bytes(), context.as_bytes())?,
        })
    }

    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.inner.update(py, data.as_bytes())
    }

    fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        data: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.inner
            .update_into(py, data.as_bytes(), buf.as_mut_bytes())
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.inner.finalize(py)
    }

    fn decrypt_range<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        source: pyo3::Bound<'p, pyo3::PyAny>,
        offset: u64,
        length: usize,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.inner.decrypt_range(py, &source, offset, length)
    }
}

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.cobblestone")]
pub(crate) struct Cobblestone256Encryptor {
    inner: ChunkedEncryptor,
}

#[pyo3::pymethods]
impl Cobblestone256Encryptor {
    #[new]
    fn new(
        py: pyo3::Python<'_>,
        key: CffiBuf<'_>,
        context: CffiBuf<'_>,
    ) -> CryptographyResult<Self> {
        Ok(Cobblestone256Encryptor {
            inner: ChunkedEncryptor::new(py, &AES_256_GCM, key.as_bytes(), context.as_bytes())?,
        })
    }

    #[staticmethod]
    fn generate_key(
        py: pyo3::Python<'_>,
    ) -> CryptographyResult<pyo3::Bound<'_, pyo3::types::PyBytes>> {
        crate::backend::rand::get_rand_bytes(py, AES_256_GCM.key_len)
    }

    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.inner.update(py, data.as_bytes())
    }

    fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        data: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.inner
            .update_into(py, data.as_bytes(), buf.as_mut_bytes())
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.inner.finalize(py)
    }
}

#[pyo3::pyclass(module = "cryptography.hazmat.bindings._rust.cobblestone")]
pub(crate) struct Cobblestone256Decryptor {
    inner: ChunkedDecryptor,
}

#[pyo3::pymethods]
impl Cobblestone256Decryptor {
    #[new]
    fn new(key: CffiBuf<'_>, context: CffiBuf<'_>) -> CryptographyResult<Self> {
        Ok(Cobblestone256Decryptor {
            inner: ChunkedDecryptor::new(&AES_256_GCM, key.as_bytes(), context.as_bytes())?,
        })
    }

    fn update<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        data: CffiBuf<'_>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.inner.update(py, data.as_bytes())
    }

    fn update_into(
        &mut self,
        py: pyo3::Python<'_>,
        data: CffiBuf<'_>,
        mut buf: CffiMutBuf<'_>,
    ) -> CryptographyResult<usize> {
        self.inner
            .update_into(py, data.as_bytes(), buf.as_mut_bytes())
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.inner.finalize(py)
    }

    fn decrypt_range<'p>(
        &mut self,
        py: pyo3::Python<'p>,
        source: pyo3::Bound<'p, pyo3::PyAny>,
        offset: u64,
        length: usize,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        self.inner.decrypt_range(py, &source, offset, length)
    }
}

#[pyo3::pymodule(gil_used = false)]
#[pyo3(name = "cobblestone")]
pub(crate) mod cobblestone_mod {
    #[pymodule_export]
    use super::{
        Cobblestone128Decryptor, Cobblestone128Encryptor, Cobblestone256Decryptor,
        Cobblestone256Encryptor,
    };
}

#[cfg(test)]
mod tests {
    use super::{ChunkNonces, MAX_CHUNK_COUNT, NONCE_LEN};

    // Reaching the chunk counter limit requires processing a 4 PiB message,
    // so this error path can't be exercised from the Python tests.
    #[test]
    fn test_chunk_nonces_counter_limit() {
        let mut nonces = ChunkNonces {
            base_nonce: [0; NONCE_LEN],
            counter: MAX_CHUNK_COUNT - 1,
        };
        assert!(nonces.check_capacity(1).is_ok());
        assert!(nonces.check_capacity(2).is_err());
        // The final counter value is usable...
        assert!(nonces.next().is_ok());
        // ...but nothing past it.
        assert!(nonces.check_capacity(0).is_ok());
        assert!(nonces.check_capacity(1).is_err());
        assert!(nonces.next().is_err());
    }
}
