// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! Reading PKCS #12 (RFC 7292) bundles, as OpenSSL's `PKCS12_parse` does,
//! with verified-garbage: the MAC is checked (password-integrity mode with
//! the PKCS #12 KDF and HMAC), encrypted contents and shrouded key bags
//! are decrypted, and the key and certificates are returned as DER, with
//! each certificate's friendly name.
//!
//! Only DER is accepted (the `asn1` crate reads no BER), and only HMAC
//! integrity (not PBMAC1, RFC 9579).

use cryptography_crypto::hash::MessageDigest;
use cryptography_x509::common::{AlgorithmIdentifier, AlgorithmParameters};
use cryptography_x509::pkcs12::{
    Pfx, CERT_BAG_OID, FRIENDLY_NAME_OID, KEY_BAG_OID, SHROUDED_KEY_BAG_OID, X509_CERTIFICATE_OID,
};
use cryptography_x509::pkcs7::{Content, ContentInfo};
use cryptography_x509::pkcs8::EncryptedPrivateKeyInfo;

const SAFE_CONTENTS_BAG_OID: asn1::ObjectIdentifier =
    asn1::oid!(1, 2, 840, 113549, 1, 12, 10, 1, 6);
/// How deeply `safeContentsBag`s may nest. Each level recurses, so without
/// a limit a crafted bundle overflows the stack. OpenSSL's ASN.1 decoder
/// refuses constructed values nested more than 30 deep, which lets through
/// at most 28 nested `safeContentsBag`s.
const MAX_SAFE_CONTENTS_DEPTH: usize = 28;
const MD5_OID: asn1::ObjectIdentifier = asn1::oid!(1, 2, 840, 113549, 2, 5);
const SHA512_224_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 5);
const SHA512_256_OID: asn1::ObjectIdentifier = asn1::oid!(2, 16, 840, 1, 101, 3, 4, 2, 6);

/// Why a bundle could not be read.
#[derive(Debug, PartialEq, Eq)]
pub enum Pkcs12Error {
    /// It is not a DER-encoded PKCS #12 `PFX`.
    Deserialize,
    /// The password is wrong (the MAC does not verify, or decryption fails),
    /// or the contents are malformed or use an unsupported algorithm.
    InvalidPasswordOrData,
}

/// A certificate of a bundle: its DER and its friendly name, as UTF-8.
#[derive(Debug, PartialEq, Eq)]
pub struct Pkcs12Certificate {
    pub der: Vec<u8>,
    pub friendly_name: Option<Vec<u8>>,
}

/// What a bundle holds: its (first) private key, as a PKCS #8
/// `PrivateKeyInfo`, and its certificates, in order. As with OpenSSL, the
/// caller pairs the key with the first certificate whose public key
/// matches it.
#[derive(Debug, PartialEq, Eq)]
pub struct Pkcs12Contents {
    pub key: Option<Vec<u8>>,
    pub certificates: Vec<Pkcs12Certificate>,
}

#[derive(asn1::Asn1Read)]
struct SafeBag<'a> {
    bag_id: asn1::ObjectIdentifier,
    bag_value: asn1::Explicit<asn1::Tlv<'a>, 0>,
    attributes: Option<asn1::SetOf<'a, Attribute<'a>>>,
}

#[derive(asn1::Asn1Read)]
struct Attribute<'a> {
    attr_id: asn1::ObjectIdentifier,
    attr_values: asn1::SetOf<'a, asn1::Tlv<'a>>,
}

#[derive(asn1::Asn1Read)]
struct CertBag<'a> {
    cert_id: asn1::ObjectIdentifier,
    cert_value: asn1::Explicit<asn1::Tlv<'a>, 0>,
}

type SafeContents<'a> = asn1::SequenceOf<'a, SafeBag<'a>>;

use Pkcs12Error::InvalidPasswordOrData as Invalid;

/// The hash of a MAC's `DigestInfo` algorithm.
fn mac_digest(alg: &AlgorithmIdentifier<'_>) -> Option<MessageDigest> {
    Some(match &alg.params {
        AlgorithmParameters::Sha1(_) => MessageDigest::Sha1,
        AlgorithmParameters::Sha224(_) => MessageDigest::Sha224,
        AlgorithmParameters::Sha256(_) => MessageDigest::Sha256,
        AlgorithmParameters::Sha384(_) => MessageDigest::Sha384,
        AlgorithmParameters::Sha512(_) => MessageDigest::Sha512,
        AlgorithmParameters::Other(oid, _) if *oid == MD5_OID => MessageDigest::Md5,
        AlgorithmParameters::Other(oid, _) if *oid == SHA512_224_OID => MessageDigest::Sha512_224,
        AlgorithmParameters::Other(oid, _) if *oid == SHA512_256_OID => MessageDigest::Sha512_256,
        // SHA-3 (verified-garbage has no HMAC over it), PBMAC1, ...
        _ => return None,
    })
}

/// A password as a BMPString with its NUL trailer, or empty for an absent
/// password.
fn bmp_password(password: Option<&[u8]>) -> Result<Vec<u8>, Pkcs12Error> {
    Ok(match password {
        None => vec![],
        Some(p) => std::str::from_utf8(p)
            .map_err(|_| Invalid)?
            .encode_utf16()
            .chain([0])
            .flat_map(|v| v.to_be_bytes())
            .collect(),
    })
}

/// Whether the bundle's MAC over `auth_safe` verifies with `password`.
fn verify_mac(
    mac_data: &cryptography_x509::pkcs12::MacData<'_>,
    auth_safe: &[u8],
    password: Option<&[u8]>,
) -> Result<bool, Pkcs12Error> {
    let md = mac_digest(&mac_data.mac.algorithm).ok_or(Invalid)?;
    if !cryptography_crypto::hmac::supported(md) {
        return Err(Invalid);
    }
    let key = cryptography_crypto::pkcs12::kdf_bmp(
        &bmp_password(password)?,
        mac_data.salt,
        cryptography_crypto::pkcs12::KDF_MAC_KEY_ID,
        mac_data.iterations,
        md.size(),
        md,
    )
    .map_err(|_| Invalid)?;
    let mut h = cryptography_crypto::hmac::Hmac::new(&key, md).map_err(|_| Invalid)?;
    h.update(auth_safe).map_err(|_| Invalid)?;
    let mac = h.finish().map_err(|_| Invalid)?;
    Ok(cryptography_crypto::constant_time::bytes_eq(
        &mac,
        mac_data.mac.digest,
    ))
}

/// A friendly name attribute's value as UTF-8 (as OpenSSL's
/// `ASN1_STRING_to_UTF8` converts it), if it is a string type.
fn friendly_name(value: &asn1::Tlv<'_>) -> Option<Vec<u8>> {
    let data = value.data();
    match value.tag().as_u8()? {
        // BMPString
        0x1e => {
            if data.len() % 2 != 0 {
                return None;
            }
            let units = data
                .chunks_exact(2)
                .map(|c| u16::from_be_bytes([c[0], c[1]]))
                .collect::<Vec<_>>();
            String::from_utf16(&units).ok().map(String::into_bytes)
        }
        // UTF8String
        0x0c => std::str::from_utf8(data)
            .ok()
            .map(|s| s.as_bytes().to_vec()),
        // PrintableString, IA5String, VisibleString
        0x13 | 0x16 | 0x1a => data.is_ascii().then(|| data.to_vec()),
        _ => None,
    }
}

struct Parser<'p> {
    password: Option<&'p [u8]>,
    contents: Pkcs12Contents,
}

impl Parser<'_> {
    /// Parses a `SafeContents` nested in `depth` `safeContentsBag`s.
    fn parse_bags(&mut self, data: &[u8], depth: usize) -> Result<(), Pkcs12Error> {
        if depth > MAX_SAFE_CONTENTS_DEPTH {
            return Err(Invalid);
        }
        let bags = asn1::parse_single::<SafeContents<'_>>(data).map_err(|_| Invalid)?;
        for bag in bags {
            self.parse_bag(bag, depth)?;
        }
        Ok(())
    }

    fn parse_bag(&mut self, bag: SafeBag<'_>, depth: usize) -> Result<(), Pkcs12Error> {
        let value = bag.bag_value.into_inner();
        match bag.bag_id {
            KEY_BAG_OID => {
                // Only the first key is used.
                if self.contents.key.is_none() {
                    self.contents.key = Some(value.full_data().to_vec());
                }
            }
            SHROUDED_KEY_BAG_OID => {
                if self.contents.key.is_none() {
                    let epki = value
                        .parse::<EncryptedPrivateKeyInfo<'_>>()
                        .map_err(|_| Invalid)?;
                    let key = crate::pkcs8::pbe_decrypt(
                        &epki.encryption_algorithm,
                        epki.encrypted_data,
                        self.password,
                    )
                    .map_err(|_| Invalid)?;
                    self.contents.key = Some(key);
                }
            }
            CERT_BAG_OID => {
                let cert_bag = value.parse::<CertBag<'_>>().map_err(|_| Invalid)?;
                if cert_bag.cert_id != X509_CERTIFICATE_OID {
                    return Ok(());
                }
                let der = cert_bag
                    .cert_value
                    .into_inner()
                    .parse::<&[u8]>()
                    .map_err(|_| Invalid)?;
                let name = bag.attributes.and_then(|attrs| {
                    let attr = attrs.clone().find(|a| a.attr_id == FRIENDLY_NAME_OID)?;
                    friendly_name(&attr.attr_values.clone().next()?)
                });
                self.contents.certificates.push(Pkcs12Certificate {
                    der: der.to_vec(),
                    friendly_name: name,
                });
            }
            SAFE_CONTENTS_BAG_OID => self.parse_bags(value.full_data(), depth + 1)?,
            // CRLs, secrets and other bags are ignored.
            _ => {}
        }
        Ok(())
    }
}

/// Reads a DER-encoded PKCS #12 bundle. An empty `password` is taken as
/// OpenSSL takes it: the bundle may have no MAC, or a MAC with an absent or
/// an empty password.
pub fn parse(data: &[u8], password: &[u8]) -> Result<Pkcs12Contents, Pkcs12Error> {
    let pfx = asn1::parse_single::<Pfx<'_>>(data).map_err(|_| Pkcs12Error::Deserialize)?;
    let Content::Data(Some(auth_safe)) = pfx.auth_safe.content else {
        return Err(Invalid);
    };
    let auth_safe = auth_safe.into_inner();

    let password = if password.is_empty() {
        match &pfx.mac_data {
            None => None,
            Some(mac_data) => {
                if verify_mac(mac_data, auth_safe, None)? {
                    None
                } else if verify_mac(mac_data, auth_safe, Some(b""))? {
                    Some(&b""[..])
                } else {
                    return Err(Invalid);
                }
            }
        }
    } else {
        match &pfx.mac_data {
            Some(mac_data) if verify_mac(mac_data, auth_safe, Some(password))? => Some(password),
            _ => return Err(Invalid),
        }
    };

    let mut parser = Parser {
        password,
        contents: Pkcs12Contents {
            key: None,
            certificates: vec![],
        },
    };
    let safes = asn1::parse_single::<asn1::SequenceOf<'_, ContentInfo<'_>>>(auth_safe)
        .map_err(|_| Invalid)?;
    for safe in safes {
        match safe.content {
            Content::Data(data) => {
                parser.parse_bags(data.ok_or(Invalid)?.into_inner(), 0)?;
            }
            Content::EncryptedData(encrypted) => {
                let info = encrypted.into_inner().encrypted_content_info;
                let plaintext = crate::pkcs8::pbe_decrypt(
                    &info.content_encryption_algorithm,
                    info.encrypted_content.ok_or(Invalid)?,
                    password,
                )
                .map_err(|_| Invalid)?;
                parser.parse_bags(&plaintext, 0)?;
            }
            // Other content types (public-key encryption) are ignored.
            _ => {}
        }
    }
    Ok(parser.contents)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! p12 {
        ($name:literal) => {
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../../vectors/cryptography_vectors/pkcs12/",
                $name
            ))
            .as_slice()
        };
    }

    #[test]
    fn test_vectors() {
        let c = parse(p12!("cert-key-aes256cbc.p12"), b"cryptography").unwrap();
        assert!(c.key.is_some());
        assert_eq!(c.certificates.len(), 1);
        assert_eq!(c.certificates[0].friendly_name, None);
        assert!(crate::pkcs8::parse_private_key(c.key.as_ref().unwrap()).is_ok());

        let c = parse(p12!("cert-none-key-none.p12"), b"cryptography").unwrap();
        assert!(c.key.is_some());
        let c = parse(p12!("cert-rc2-key-3des.p12"), b"cryptography").unwrap();
        assert!(c.key.is_some());
        assert_eq!(c.certificates.len(), 1);

        let c = parse(p12!("cert-aes256cbc-no-key.p12"), b"cryptography").unwrap();
        assert!(c.key.is_none());
        assert_eq!(c.certificates.len(), 1);

        let c = parse(p12!("name-all-no-pwd.p12"), b"").unwrap();
        let names = c
            .certificates
            .iter()
            .map(|c| c.friendly_name.clone())
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&Some(b"name".to_vec())));
        assert!(names.contains(&Some(b"name2".to_vec())));
        assert!(names.contains(&Some(b"name3".to_vec())));

        let c = parse(p12!("name-unicode-pwd.p12"), b"password").unwrap();
        assert!(c
            .certificates
            .iter()
            .any(|c| c.friendly_name == Some("☺".as_bytes().to_vec())));

        let c = parse(p12!("no-cert-no-name-no-pwd.p12"), b"").unwrap();
        assert!(c.key.is_none());
        assert_eq!(c.certificates.len(), 2);
    }

    #[test]
    fn test_errors() {
        assert_eq!(parse(b"invalid", b"pass"), Err(Pkcs12Error::Deserialize));
        assert_eq!(
            parse(p12!("cert-key-aes256cbc.p12"), b"invalid"),
            Err(Pkcs12Error::InvalidPasswordOrData)
        );
        assert_eq!(
            parse(p12!("cert-key-aes256cbc.p12"), b""),
            Err(Pkcs12Error::InvalidPasswordOrData)
        );
        assert_eq!(
            parse(p12!("name-all-pwd.p12"), b"\xff"),
            Err(Pkcs12Error::InvalidPasswordOrData)
        );
        // A BER bundle.
        assert_eq!(
            parse(p12!("no-password.p12"), b""),
            Err(Pkcs12Error::Deserialize)
        );
    }

    #[test]
    fn test_friendly_name() {
        let tlv = |der: &'static [u8]| asn1::parse_single::<asn1::Tlv<'_>>(der).unwrap();
        assert_eq!(friendly_name(&tlv(b"\x1e\x02\x00a")), Some(b"a".to_vec()));
        assert_eq!(friendly_name(&tlv(b"\x1e\x01\x00")), None);
        assert_eq!(friendly_name(&tlv(b"\x0c\x01a")), Some(b"a".to_vec()));
        assert_eq!(friendly_name(&tlv(b"\x13\x01a")), Some(b"a".to_vec()));
        assert_eq!(friendly_name(&tlv(b"\x04\x01a")), None);
    }

    /// A DER TLV.
    fn der(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        if body.len() < 0x80 {
            out.push(body.len() as u8);
        } else {
            let len = body.len().to_be_bytes();
            let len = &len[len.iter().position(|&b| b != 0).unwrap()..];
            out.push(0x80 | len.len() as u8);
            out.extend_from_slice(len);
        }
        out.extend_from_slice(body);
        out
    }

    /// A bundle without a MAC whose (empty) `SafeContents` is nested in
    /// `depth` `safeContentsBag`s.
    fn nested_bundle(depth: usize) -> Vec<u8> {
        let bag_id = asn1::write_single(&SAFE_CONTENTS_BAG_OID).unwrap();
        let data_id = asn1::write_single(&cryptography_x509::pkcs7::PKCS7_DATA_OID).unwrap();
        let mut contents = der(0x30, b"");
        for _ in 0..depth {
            let bag = der(0x30, &[&bag_id[..], &der(0xa0, &contents)].concat());
            contents = der(0x30, &bag);
        }
        let safe = der(
            0x30,
            &[&data_id[..], &der(0xa0, &der(0x04, &contents))].concat(),
        );
        let auth_safe = der(0x30, &safe);
        let content_info = der(
            0x30,
            &[&data_id[..], &der(0xa0, &der(0x04, &auth_safe))].concat(),
        );
        der(0x30, &[&b"\x02\x01\x03"[..], &content_info].concat())
    }

    #[test]
    fn test_nested_safe_contents() {
        let empty = Pkcs12Contents {
            key: None,
            certificates: vec![],
        };
        assert_eq!(parse(&nested_bundle(1), b""), Ok(empty));
        assert!(parse(&nested_bundle(MAX_SAFE_CONTENTS_DEPTH), b"").is_ok());
        assert_eq!(
            parse(&nested_bundle(MAX_SAFE_CONTENTS_DEPTH + 1), b""),
            Err(Pkcs12Error::InvalidPasswordOrData)
        );
        // Deep enough to overflow the stack without the limit.
        assert_eq!(
            parse(&nested_bundle(100_000), b""),
            Err(Pkcs12Error::InvalidPasswordOrData)
        );
    }
}
