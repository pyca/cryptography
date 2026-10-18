// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Legacy PEM encryption (`Proc-Type` and `DEK-Info` headers), with
//! verified-garbage.

use std::borrow::Cow;

use crate::vg_cipher::Cipher;
use crate::{KeyParsingError, KeyParsingResult};

/// Decrypts PEM encryption (legacy format with Proc-Type and DEK-Info headers).
/// Returns a tuple of (decrypted contents, was_encrypted flag).
///
/// If no `Proc-Type` header is present, the PEM contents is returned
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
                "AES-128-CBC" => Cipher::Aes128Cbc,
                "AES-256-CBC" => Cipher::Aes256Cbc,
                "DES-EDE3-CBC" => Cipher::DesEde3Cbc,
                _ => return Err(KeyParsingError::PemUnsupportedCipher),
            };

            let iv = cryptography_crypto::encoding::hex_decode(iv)
                .ok_or(KeyParsingError::PemInvalidIv)?;

            let key = cryptography_crypto::pbkdf1::openssl_kdf(
                cryptography_crypto::hash::MessageDigest::md5(),
                password,
                iv.get(..8)
                    .ok_or(KeyParsingError::PemInvalidIv)?
                    .try_into()
                    .unwrap(),
                cipher.key_len(),
            )
            .map_err(|_| KeyParsingError::PemUnableToDeriveKey)?;

            // An IV of the wrong length for the cipher fails here, as it
            // does with OpenSSL.
            let decrypted = cipher
                .decrypt(&key, &iv, pem.contents())
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

    let cipher = Cipher::Aes256Cbc;
    let mut iv = vec![0u8; cipher.iv_len()];
    crate::vg_util::rand_bytes(&mut iv)?;

    // Derive key using MD5-based KDF (for compatibility with traditional
    // OpenSSL format)
    let key = cryptography_crypto::pbkdf1::openssl_kdf(
        cryptography_crypto::hash::MessageDigest::md5(),
        password,
        iv[..8].try_into().unwrap(),
        cipher.key_len(),
    )?;

    let encrypted = cipher.encrypt(&key, &iv, der_data);

    let iv_hex = cryptography_crypto::encoding::hex_encode(&iv);

    let mut pem = pem::Pem::new(tag, encrypted);
    pem.headers_mut().add("Proc-Type", "4,ENCRYPTED").unwrap();
    pem.headers_mut()
        .add("DEK-Info", &format!("AES-256-CBC,{iv_hex}"))
        .unwrap();

    Ok(pem::encode_config(&pem, ENCODE_CONFIG).into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vg_util::vector;

    fn pem(path: &[u8]) -> pem::Pem {
        pem::parse(path).unwrap()
    }

    #[test]
    fn test_decrypt_vectors() {
        let plain = pem(vector!("Traditional_OpenSSL_Serialization/testrsa.pem"));
        let encrypted = pem(vector!(
            "Traditional_OpenSSL_Serialization/testrsa-encrypted.pem"
        ));
        let (der, was_encrypted) = decrypt_pem(&encrypted, Some(b"password")).ok().unwrap();
        assert!(was_encrypted);
        assert_eq!(&der[..], plain.contents());
        assert!(matches!(
            decrypt_pem(&encrypted, Some(b"wrong")),
            Err(KeyParsingError::IncorrectPassword)
        ));
        for password in [None, Some(&b""[..])] {
            assert!(matches!(
                decrypt_pem(&encrypted, password),
                Err(KeyParsingError::EncryptedKeyWithoutPassword)
            ));
        }

        let (der, was_encrypted) = decrypt_pem(&plain, None).ok().unwrap();
        assert!(!was_encrypted);
        assert_eq!(&der[..], plain.contents());

        for (path, password) in [
            (
                vector!("Traditional_OpenSSL_Serialization/key1.pem"),
                &b"123456"[..],
            ),
            (
                vector!("Traditional_OpenSSL_Serialization/key2.pem"),
                b"a123456",
            ),
        ] {
            let p = pem(path);
            let (der, was_encrypted) = decrypt_pem(&p, Some(password)).ok().unwrap();
            assert!(was_encrypted);
            assert!(crate::rsa::parse_pkcs1_private_key(&der).is_ok());
        }
        // DES-EDE3-CBC.
        let p = pem(vector!("PEM_Serialization/rsa_private_key.pem"));
        let (der, _) = decrypt_pem(&p, Some(b"123456")).ok().unwrap();
        assert!(crate::rsa::parse_pkcs1_private_key(&der).is_ok());
        let p = pem(vector!("PEM_Serialization/dsa_private_key.pem"));
        let (der, _) = decrypt_pem(&p, Some(b"123456")).ok().unwrap();
        assert!(crate::dsa::parse_pkcs1_private_key(&der).is_ok());

        let ec = pem(vector!("PEM_Serialization/ec_private_key_encrypted.pem"));
        let (der, _) = decrypt_pem(&ec, Some(b"123456")).ok().unwrap();
        assert!(crate::ec::parse_pkcs1_private_key(&der, None).is_ok());
    }

    #[test]
    fn test_decrypt_errors() {
        assert!(matches!(
            decrypt_pem(
                &pem(vector!(
                    "Traditional_OpenSSL_Serialization/key1-no-dek-info.pem"
                )),
                Some(b"123456")
            ),
            Err(KeyParsingError::PemMissingDekInfo)
        ));
        assert!(matches!(
            decrypt_pem(
                &pem(vector!(
                    "Traditional_OpenSSL_Serialization/key1-malformed-dek-info.pem"
                )),
                Some(b"123456")
            ),
            Err(KeyParsingError::PemInvalidDekInfo)
        ));
        assert!(matches!(
            decrypt_pem(
                &pem(vector!(
                    "Traditional_OpenSSL_Serialization/key1-malformed-iv.pem"
                )),
                Some(b"123456")
            ),
            Err(KeyParsingError::PemInvalidIv)
        ));
        assert!(matches!(
            decrypt_pem(
                &pem(vector!(
                    "Traditional_OpenSSL_Serialization/key1-short-iv.pem"
                )),
                Some(b"123456")
            ),
            Err(KeyParsingError::PemInvalidIv)
        ));

        let mut p = pem::Pem::new("RSA PRIVATE KEY", vec![0; 16]);
        p.headers_mut().add("Proc-Type", "4,ENCRYPTED").unwrap();
        p.headers_mut()
            .add("DEK-Info", "FAKE-123,5E22A2BD85A653FB7A3ED20DE84F54CD")
            .unwrap();
        assert!(matches!(
            decrypt_pem(&p, Some(b"pw")),
            Err(KeyParsingError::PemUnsupportedCipher)
        ));

        // An IV of the wrong length for the cipher.
        let mut p = pem::Pem::new("RSA PRIVATE KEY", vec![0; 16]);
        p.headers_mut().add("Proc-Type", "4,ENCRYPTED").unwrap();
        p.headers_mut()
            .add("DEK-Info", "AES-128-CBC,5E22A2BD85A653FB")
            .unwrap();
        assert!(matches!(
            decrypt_pem(&p, Some(b"pw")),
            Err(KeyParsingError::IncorrectPassword)
        ));

        let mut p = pem::Pem::new("RSA PRIVATE KEY", vec![0; 16]);
        p.headers_mut().add("Proc-Type", "<,ENCRYPTED").unwrap();
        assert!(matches!(
            decrypt_pem(&p, Some(b"pw")),
            Err(KeyParsingError::PemInvalidProcType)
        ));
    }

    #[test]
    fn test_encrypt_round_trip() {
        let der = b"some DER data that is longer than a block";
        let encoded = encrypt_pem("RSA PRIVATE KEY", der, b"").ok().unwrap();
        let p = pem::parse(&encoded).unwrap();
        assert!(p.headers().get("Proc-Type").is_none());
        assert_eq!(p.contents(), der);

        let encoded = encrypt_pem("RSA PRIVATE KEY", der, b"hunter2")
            .ok()
            .unwrap();
        let p = pem::parse(&encoded).unwrap();
        assert_eq!(p.tag(), "RSA PRIVATE KEY");
        assert_eq!(p.headers().get("Proc-Type"), Some("4,ENCRYPTED"));
        assert!(p
            .headers()
            .get("DEK-Info")
            .unwrap()
            .starts_with("AES-256-CBC,"));
        let (decrypted, was_encrypted) = decrypt_pem(&p, Some(b"hunter2")).ok().unwrap();
        assert!(was_encrypted);
        assert_eq!(&decrypted[..], der);
    }
}
