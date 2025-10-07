// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::borrow::Cow;

use crate::{KeyParsingError, KeyParsingResult};

/// Decrypts PEM encryption (legacy format with Proc-Type and DEK-Info headers).
/// Returns a tuple of (decrypted contents, was_encrypted flag).
///
/// If no `Proc-Type` header is preseent, the PEM contents is returned
/// undecrypted.
///
/// Supported ciphers: AES-128-CBC, AES-256-CBC, DES-EDE3-CBC
pub fn decrypt_pem<'a>(
    pem: &'a pem::Pem,
    password: Option<&[u8]>,
) -> KeyParsingResult<(Cow<'a, [u8]>, bool)> {
    match pem.headers().get("Proc-Type") {
        Some("4,ENCRYPTED") => {
            let dek_info = pem
                .headers()
                .get("DEK-Info")
                .ok_or(KeyParsingError::PemMissingDekInfo)?;

            let (cipher_algorithm, iv) = dek_info
                .split_once(',')
                .ok_or(KeyParsingError::PemInvalidDekInfo)?;

            let password = match password {
                None | Some(b"") => return Err(KeyParsingError::EncryptedKeyWithoutPassword),
                Some(p) => p,
            };

            // There's no RFC that defines these, but these are the ones in
            // very wide use that we support.
            let cipher = match cipher_algorithm {
                "AES-128-CBC" => openssl::symm::Cipher::aes_128_cbc(),
                "AES-256-CBC" => openssl::symm::Cipher::aes_256_cbc(),
                "DES-EDE3-CBC" => openssl::symm::Cipher::des_ede3_cbc(),
                _ => return Err(KeyParsingError::PemUnsupportedCipher),
            };

            let iv = cryptography_crypto::encoding::hex_decode(iv)
                .ok_or(KeyParsingError::PemInvalidIv)?;

            let key = cryptography_crypto::pbkdf1::openssl_kdf(
                openssl::hash::MessageDigest::md5(),
                password,
                iv.get(..8)
                    .ok_or(KeyParsingError::PemInvalidIv)?
                    .try_into()
                    .unwrap(),
                cipher.key_len(),
            )
            .map_err(|_| KeyParsingError::PemUnableToDeriveKey)?;

            let decrypted = openssl::symm::decrypt(cipher, &key, Some(&iv), pem.contents())
                .map_err(|_| KeyParsingError::IncorrectPassword)?;

            Ok((Cow::Owned(decrypted), true))
        }
        Some(_) => Err(KeyParsingError::PemInvalidProcType),
        None => Ok((Cow::Borrowed(pem.contents()), false)),
    }
}
