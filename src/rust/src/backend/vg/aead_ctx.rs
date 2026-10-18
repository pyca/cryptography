// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! The verified-garbage AEADs behind `backend/aead.rs`: one-shot encryption
//! and decryption with the interface of the OpenSSL build's
//! `EvpCipherAead`, which the Python-facing classes call after their own
//! validation.

use verified_garbage::aes_ccm::AesCcm;
use verified_garbage::aes_gcm::AesGcm;
use verified_garbage::aes_gcm_siv::AesGcmSiv;
use verified_garbage::aes_ocb::AesOcb;
use verified_garbage::aes_siv::AesSiv;
use verified_garbage::chacha20poly1305::ChaCha20Poly1305;

use super::{check_length, extract_aad, Aad, ExtractedAad};
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

enum Key {
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
    AesGcm(Box<AesGcm>),
    AesCcm(Box<AesCcm>),
    AesSiv(Box<AesSiv>),
    AesOcb(Box<AesOcb>),
    AesGcmSiv(Box<AesGcmSiv>),
}

/// A key for one of the AEADs, and its tag length.
pub(crate) struct VgAead {
    key: Key,
    pub(crate) tag_len: usize,
}

fn bad_key() -> CryptographyError {
    CryptographyError::VerifiedGarbage("invalid AEAD key")
}

fn failed<E>(_: E) -> CryptographyError {
    CryptographyError::VerifiedGarbage("AEAD encryption failed")
}

fn bad_nonce() -> CryptographyError {
    CryptographyError::VerifiedGarbage("invalid AEAD nonce")
}

/// The lengths of a CCM tag (SP 800-38C Appendix A.1), for which
/// verified-garbage's AES-CCM takes the length as a type parameter.
macro_rules! ccm_tag_length {
    ($len:expr, $t:ident => $e:expr) => {
        match $len {
            4 => {
                const $t: usize = 4;
                $e
            }
            6 => {
                const $t: usize = 6;
                $e
            }
            8 => {
                const $t: usize = 8;
                $e
            }
            10 => {
                const $t: usize = 10;
                $e
            }
            12 => {
                const $t: usize = 12;
                $e
            }
            14 => {
                const $t: usize = 14;
                $e
            }
            16 => {
                const $t: usize = 16;
                $e
            }
            _ => Err(CryptographyError::VerifiedGarbage("invalid AES-CCM tag length")),
        }
    };
}

impl VgAead {
    pub(crate) fn chacha20_poly1305(key: &[u8]) -> CryptographyResult<VgAead> {
        let key: &[u8; 32] = key.try_into().map_err(|_| bad_key())?;
        Ok(VgAead {
            key: Key::ChaCha20Poly1305(Box::new(ChaCha20Poly1305::new(key))),
            tag_len: 16,
        })
    }

    pub(crate) fn aes_gcm(key: &[u8]) -> CryptographyResult<VgAead> {
        Ok(VgAead {
            key: Key::AesGcm(Box::new(AesGcm::new(key).map_err(|_| bad_key())?)),
            tag_len: 16,
        })
    }

    pub(crate) fn aes_ccm(key: &[u8], tag_len: usize) -> CryptographyResult<VgAead> {
        Ok(VgAead {
            key: Key::AesCcm(Box::new(AesCcm::new(key).map_err(|_| bad_key())?)),
            tag_len,
        })
    }

    pub(crate) fn aes_siv(key: &[u8]) -> CryptographyResult<VgAead> {
        Ok(VgAead {
            key: Key::AesSiv(Box::new(AesSiv::new(key).map_err(|_| bad_key())?)),
            tag_len: 16,
        })
    }

    pub(crate) fn aes_ocb3(key: &[u8]) -> CryptographyResult<VgAead> {
        Ok(VgAead {
            key: Key::AesOcb(Box::new(AesOcb::new(key).map_err(|_| bad_key())?)),
            tag_len: 16,
        })
    }

    /// AES-GCM-SIV with a 128- or 256-bit key (verified-garbage has no
    /// 192-bit AES-GCM-SIV: the caller rejects that first).
    pub(crate) fn aes_gcm_siv(key: &[u8]) -> CryptographyResult<VgAead> {
        Ok(VgAead {
            key: Key::AesGcmSiv(Box::new(AesGcmSiv::new(key).map_err(|_| bad_key())?)),
            tag_len: 16,
        })
    }

    /// Encrypts `data` in place and writes its tag (of `tag_len` bytes).
    fn seal(
        &self,
        aad: &ExtractedAad<'_>,
        nonce: Option<&[u8]>,
        data: &mut [u8],
        tag: &mut [u8],
    ) -> CryptographyResult<()> {
        let single = single_aad(aad);
        let nonce12 = || -> CryptographyResult<&[u8; 12]> {
            nonce.and_then(|n| n.try_into().ok()).ok_or_else(bad_nonce)
        };
        match &self.key {
            Key::ChaCha20Poly1305(k) => tag.copy_from_slice(
                &k.encrypt_in_place(nonce12()?, single, data)
                    .map_err(failed)?,
            ),
            Key::AesGcm(k) => tag.copy_from_slice(
                &k.encrypt_in_place(nonce.ok_or_else(bad_nonce)?, single, data)
                    .map_err(failed)?,
            ),
            Key::AesGcmSiv(k) => tag.copy_from_slice(
                &k.encrypt_in_place(nonce12()?, single, data)
                    .map_err(failed)?,
            ),
            Key::AesOcb(k) => tag.copy_from_slice(
                &k.encrypt_in_place::<16>(nonce.ok_or_else(bad_nonce)?, single, data)
                    .map_err(failed)?,
            ),
            Key::AesCcm(k) => {
                let nonce = nonce.ok_or_else(bad_nonce)?;
                ccm_tag_length!(tag.len(), T => {
                    tag.copy_from_slice(
                        &k.encrypt_in_place::<T>(nonce, single, data).map_err(failed)?,
                    );
                    Ok(())
                })?
            }
            Key::AesSiv(k) => {
                let ads = siv_aad(aad)?;
                tag.copy_from_slice(&k.encrypt_in_place(&ads, data).map_err(failed)?)
            }
        }
        Ok(())
    }

    /// Decrypts `data` in place if `tag` authenticates it; returns whether
    /// it did.
    fn open(
        &self,
        aad: &ExtractedAad<'_>,
        nonce: Option<&[u8]>,
        data: &mut [u8],
        tag: &[u8],
    ) -> CryptographyResult<bool> {
        let single = single_aad(aad);
        let nonce12 = || -> CryptographyResult<&[u8; 12]> {
            nonce.and_then(|n| n.try_into().ok()).ok_or_else(bad_nonce)
        };
        let tag16 = || -> CryptographyResult<&[u8; 16]> {
            tag.try_into()
                .map_err(|_| CryptographyError::VerifiedGarbage("invalid AEAD tag length"))
        };
        Ok(match &self.key {
            Key::ChaCha20Poly1305(k) => k
                .decrypt_in_place(nonce12()?, single, data, tag16()?)
                .is_ok(),
            Key::AesGcm(k) => k
                .decrypt_in_place(nonce.ok_or_else(bad_nonce)?, single, data, tag16()?)
                .is_ok(),
            Key::AesGcmSiv(k) => k
                .decrypt_in_place(nonce12()?, single, data, tag16()?)
                .is_ok(),
            Key::AesOcb(k) => k
                .decrypt_in_place::<16>(nonce.ok_or_else(bad_nonce)?, single, data, tag16()?)
                .is_ok(),
            Key::AesCcm(k) => {
                let nonce = nonce.ok_or_else(bad_nonce)?;
                ccm_tag_length!(tag.len(), T => {
                    Ok(k.decrypt_in_place::<T>(nonce, single, data, tag.try_into().unwrap())
                        .is_ok())
                })?
            }
            Key::AesSiv(k) => {
                let ads = siv_aad(aad)?;
                k.decrypt_in_place(&ads, data, tag16()?).is_ok()
            }
        })
    }

    pub(crate) fn encrypt_into(
        &self,
        py: pyo3::Python<'_>,
        plaintext: &[u8],
        aad: Option<Aad<'_>>,
        nonce: Option<&[u8]>,
        buf: &mut [u8],
    ) -> CryptographyResult<()> {
        check_length(plaintext)?;
        crate::buf::check_no_overlap(plaintext, buf)?;

        let tag_first = matches!(self.key, Key::AesSiv(_));
        let (ciphertext, tag) = if tag_first {
            let (tag, ciphertext) = buf.split_at_mut(self.tag_len);
            (ciphertext, tag)
        } else {
            buf.split_at_mut(plaintext.len())
        };

        let (aad, aad_len) = extract_aad(aad)?;
        crate::backend::run_with_gil_detached(py, plaintext.len() + aad_len, || {
            ciphertext.copy_from_slice(plaintext);
            self.seal(&aad, nonce, ciphertext, tag)
        })
    }

    pub(crate) fn decrypt_into(
        &self,
        py: pyo3::Python<'_>,
        ciphertext: &[u8],
        aad: Option<Aad<'_>>,
        nonce: Option<&[u8]>,
        buf: &mut [u8],
    ) -> CryptographyResult<()> {
        crate::buf::check_no_overlap(ciphertext, buf)?;

        let (tag, ciphertext_data) = if matches!(self.key, Key::AesSiv(_)) {
            // RFC 5297 defines the output as IV || C, where the tag we
            // generate is the "IV" and C is the ciphertext.
            ciphertext.split_at(self.tag_len)
        } else {
            let (c, t) = ciphertext.split_at(ciphertext.len() - self.tag_len);
            (t, c)
        };

        let (aad, aad_len) = extract_aad(aad)?;
        let ok =
            crate::backend::run_with_gil_detached(py, ciphertext_data.len() + aad_len, || {
                buf.copy_from_slice(ciphertext_data);
                self.open(&aad, nonce, buf, tag)
            })?;
        if !ok {
            return Err(CryptographyError::from(exceptions::InvalidTag::new_err(())));
        }
        Ok(())
    }
}

/// The additional data of the AEADs that take one string.
fn single_aad<'a>(aad: &'a ExtractedAad<'_>) -> &'a [u8] {
    match aad {
        ExtractedAad::None => b"",
        ExtractedAad::Single(ad) => ad.as_bytes(),
        // Only AES-SIV takes a list.
        ExtractedAad::List(_) => unreachable!("only AES-SIV takes a list of additional data"),
    }
}

/// AES-SIV's associated-data components.
fn siv_aad<'a>(aad: &'a ExtractedAad<'_>) -> CryptographyResult<Vec<&'a [u8]>> {
    let ads: Vec<&[u8]> = match aad {
        ExtractedAad::None => vec![],
        ExtractedAad::Single(ad) => vec![ad.as_bytes()],
        ExtractedAad::List(ads) => ads.iter().map(|ad| ad.as_bytes()).collect(),
    };
    if ads.len() > AesSiv::MAX_COMPONENTS {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err(format!(
                "AES-SIV takes at most {} associated data items on this backend",
                AesSiv::MAX_COMPONENTS
            )),
        ));
    }
    Ok(ads)
}

#[cfg(test)]
mod tests {
    use super::{ExtractedAad, VgAead};

    fn roundtrip(aead: &VgAead, nonce: Option<&[u8]>, expected: Option<(&[u8], &[u8])>) {
        let data: Vec<u8> = (0..50u8).collect();
        let mut ct = data.clone();
        let mut tag = vec![0; aead.tag_len];
        assert!(aead
            .seal(&ExtractedAad::None, nonce, &mut ct, &mut tag)
            .is_ok());
        if let Some((expected_ct, expected_tag)) = expected {
            assert_eq!(ct, expected_ct);
            assert_eq!(tag, expected_tag);
        }
        let mut pt = ct.clone();
        assert!(matches!(
            aead.open(&ExtractedAad::None, nonce, &mut pt, &tag),
            Ok(true)
        ));
        assert_eq!(pt, data);
        tag[0] ^= 1;
        let mut pt = ct.clone();
        assert!(matches!(
            aead.open(&ExtractedAad::None, nonce, &mut pt, &tag),
            Ok(false)
        ));
    }

    #[test]
    fn test_ccm_tag_lengths() {
        let key = [7u8; 16];
        let nonce = [9u8; 13];
        for tag_len in [4, 6, 8, 10, 12, 14, 16] {
            let aead = VgAead::aes_ccm(&key, tag_len).unwrap_or_else(|_| panic!());
            roundtrip(&aead, Some(&nonce), None);
        }
        // Against verified-garbage's one-shot AES-CCM with a 16-byte tag.
        let mut ct: Vec<u8> = (0..50u8).collect();
        let tag = verified_garbage::aes_ccm::AesCcm::new(&key)
            .unwrap()
            .encrypt_in_place::<16>(&nonce, b"", &mut ct)
            .unwrap();
        let aead = VgAead::aes_ccm(&key, 16).unwrap_or_else(|_| panic!());
        roundtrip(&aead, Some(&nonce), Some((&ct, &tag)));
    }

    #[test]
    fn test_aeads() {
        let key = [3u8; 64];
        let nonce = [5u8; 12];
        for aead in [
            VgAead::chacha20_poly1305(&key[..32]),
            VgAead::aes_gcm(&key[..24]),
            VgAead::aes_ocb3(&key[..32]),
            VgAead::aes_gcm_siv(&key[..16]),
        ] {
            roundtrip(&aead.unwrap_or_else(|_| panic!()), Some(&nonce), None);
        }
        roundtrip(
            &VgAead::aes_siv(&key).unwrap_or_else(|_| panic!()),
            None,
            None,
        );
        assert!(VgAead::aes_gcm_siv(&key[..24]).is_err());
    }
}
