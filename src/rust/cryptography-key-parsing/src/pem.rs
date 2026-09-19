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
                "AES-128-CBC" => openssl_bridge::cipher::Cipher::Aes128Cbc,
                "AES-256-CBC" => openssl_bridge::cipher::Cipher::Aes256Cbc,
                "DES-EDE3-CBC" => openssl_bridge::cipher::Cipher::TripleDesCbc,
                _ => return Err(KeyParsingError::PemUnsupportedCipher),
            };

            let iv = cryptography_crypto::encoding::hex_decode(iv)
                .ok_or(KeyParsingError::PemInvalidIv)?;

            let key = cryptography_crypto::pbkdf1::openssl_kdf(
                openssl_bridge::hash::Algorithm::from_name("md5")?,
                password,
                iv.get(..8)
                    .ok_or(KeyParsingError::PemInvalidIv)?
                    .try_into()
                    .unwrap(),
                cipher.default_key_size()?,
            )
            .map_err(|_| KeyParsingError::PemUnableToDeriveKey)?;

            let decrypted =
                openssl_bridge::cipher::decrypt_padded(cipher, &key, &iv, pem.contents())
                    .map_err(|_| KeyParsingError::IncorrectPassword)?;

            Ok((Cow::Owned(decrypted), true))
        }
        Some(_) => Err(KeyParsingError::PemInvalidProcType),
        None => Ok((Cow::Borrowed(pem.contents()), false)),
    }
}

/// PEM encoding configuration using LF line endings (Unix-style)
pub const ENCODE_CONFIG: pem::EncodeConfig =
    pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF);

/// Encrypts DER data with legacy PEM encryption (Proc-Type and DEK-Info
/// headers). Returns PEM-formatted bytes with encryption headers.
///
/// If password is empty, returns unencrypted PEM. Otherwise, encrypts using
/// AES-256-CBC.
pub fn encrypt_pem(
    tag: &str,
    der_data: &[u8],
    password: &[u8],
) -> crate::KeySerializationResult<Vec<u8>> {
    if password.is_empty() {
        // No encryption - just encode as PEM
        let pem = pem::Pem::new(tag, der_data);
        return Ok(pem::encode_config(&pem, ENCODE_CONFIG).into_bytes());
    }

    let cipher = openssl_bridge::cipher::Cipher::Aes256Cbc;
    let iv_len = cipher.iv_size()?;
    let mut iv = vec![0u8; iv_len];
    openssl_bridge::rand::fill_private(&mut iv)?;

    // Derive key using MD5-based KDF (for compatibility with traditional
    // OpenSSL format)
    let key = cryptography_crypto::pbkdf1::openssl_kdf(
        openssl_bridge::hash::Algorithm::from_name("md5")?,
        password,
        iv.get(..8).unwrap().try_into().unwrap(),
        cipher.default_key_size()?,
        // Algorithms and lengths are validated above. LLVM attributes the native KDF
        // allocation/provider failure edge to this delimiter.
        // NO-COVERAGE-START
    )?;
    // NO-COVERAGE-END

    // Encrypt the DER data
    let encrypted = openssl_bridge::cipher::encrypt_padded(cipher, &key, &iv, der_data)?;

    let iv_hex = cryptography_crypto::encoding::hex_encode(&iv);

    let mut pem = pem::Pem::new(tag, encrypted);
    pem.headers_mut().add("Proc-Type", "4,ENCRYPTED").unwrap();
    pem.headers_mut()
        .add("DEK-Info", &format!("AES-256-CBC,{iv_hex}"))
        .unwrap();

    Ok(pem::encode_config(&pem, ENCODE_CONFIG).into_bytes())
}
