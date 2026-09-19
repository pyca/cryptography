use openssl_bridge::containers::{parse_pkcs12, Pkcs12Error};

#[test]
fn pkcs12_owned_outputs_and_failures() {
    let bytes = include_bytes!("vectors/cert-key-aes256cbc.p12");
    let parsed = parse_pkcs12(bytes, Some(c"cryptography")).unwrap();
    assert!(!parsed.private_key.unwrap().as_ref().is_empty());
    assert_eq!(
        parsed.certificate.unwrap().der,
        include_bytes!("vectors/pkcs12-ca.der")
    );
    assert!(parsed.additional_certificates.is_empty());
    assert!(matches!(
        parse_pkcs12(bytes, Some(c"wrong")),
        Err(Pkcs12Error::PasswordOrData(_))
    ));
    // BoringSSL defers ASN.1 decoding from d2i_PKCS12 until PKCS12_parse.
    assert!(parse_pkcs12(b"invalid", None).is_err());
    // Failed decodes and password checks must not damage subsequent operations.
    assert!(parse_pkcs12(bytes, Some(c"cryptography")).is_ok());
}

#[test]
fn pkcs12_optional_key_and_certificate() {
    let cert = parse_pkcs12(
        include_bytes!("vectors/cert-aes256cbc-no-key.p12"),
        Some(c"cryptography"),
    )
    .unwrap();
    assert!(cert.private_key.is_none());
    assert!(cert.certificate.is_none());
    assert_eq!(cert.additional_certificates.len(), 1);
    assert_eq!(
        cert.additional_certificates[0].der,
        include_bytes!("vectors/pkcs12-ca.der")
    );
    let key = parse_pkcs12(
        include_bytes!("vectors/no-cert-key-aes256cbc.p12"),
        Some(c"cryptography"),
    )
    .unwrap();
    assert!(key.private_key.is_some());
    assert!(key.certificate.is_none());
    assert!(key.additional_certificates.is_empty());
}

#[cfg(any(backend = "openssl", backend = "libressl"))]
#[test]
fn pkcs7_certificates_and_wrong_content() {
    use openssl_bridge::containers::{parse_pkcs7_certificates, Pkcs7Certificates};
    match parse_pkcs7_certificates(include_bytes!("vectors/amazon-roots.der")).unwrap() {
        Pkcs7Certificates::Signed(Some(certs)) => {
            assert_eq!(certs.len(), 2);
            assert!(certs.iter().all(|cert| cert.first() == Some(&0x30)));
        }
        _ => panic!("expected signed certificate collection"),
    }
    // ContentInfo carrying the pkcs7-data OID, with no content.
    let data = b"\x30\x0b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01";
    assert!(matches!(
        parse_pkcs7_certificates(data),
        Ok(Pkcs7Certificates::Other(Some(_)))
    ));
    assert!(parse_pkcs7_certificates(b"invalid").is_err());
}
