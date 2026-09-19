use openssl_bridge::x509::{
    Certificate, Encoding, Name, NameField, TimeField, TrustStore, VerificationError,
};

#[test]
fn owned_names_and_failed_updates() {
    let mut cert = Certificate::empty().unwrap();
    let mut subject = cert.name(NameField::Subject).unwrap();
    subject.set(c"CN", b"original").unwrap();
    cert.set_name(NameField::Subject, &mut subject).unwrap();
    // The certificate owns an independent name, never an alias of the caller.
    subject.set(c"CN", b"later").unwrap();
    assert_eq!(
        cert.name(NameField::Subject)
            .unwrap()
            .get(c"CN")
            .unwrap()
            .as_deref(),
        Some("original")
    );
    subject.set(c"C", b"US").unwrap();
    let before = subject.der().unwrap();
    assert!(subject.set(c"C", b"too long").is_err());
    assert_eq!(subject.der().unwrap(), before);
    assert!(subject.set(c"no_such_attribute", b"x").is_err());
    assert_eq!(subject.der().unwrap(), before);
    let mut decoded = Name::from_der(&before).unwrap();
    assert_eq!(decoded.compare(&mut subject), std::cmp::Ordering::Equal);
    let mut trailing = before;
    trailing.push(0);
    assert!(Name::from_der(&trailing).is_err());
}

#[test]
fn certificate_fields_preserve_owned_values() {
    let mut cert = Certificate::empty().unwrap();
    assert_eq!(cert.time(TimeField::NotBefore).unwrap(), None);
    cert.set_time(TimeField::NotBefore, c"20260102030405Z")
        .unwrap();
    assert!(cert.set_time(TimeField::NotBefore, c"invalid").is_err());
    assert_eq!(
        cert.time(TimeField::NotBefore).unwrap().unwrap(),
        b"20260102030405Z"
    );
    let serial = [0x80; 32];
    cert.set_serial(&serial).unwrap();
    assert_eq!(cert.serial().unwrap(), (false, serial.to_vec()));
    assert!(cert.signature_algorithm().is_err());
    assert!(cert.public_key_der().is_err());
    assert!(cert.encode(Encoding::Der).is_err());
}

#[test]
fn trust_store_copies_anchors_and_verification_diagnostics() {
    let der = include_bytes!("vectors/pkcs12-ca.der");
    let mut cert = Certificate::decode(der, Encoding::Der).unwrap();
    let mut store = TrustStore::new().unwrap();
    // Use a deterministic time within the test certificate's validity interval.
    store.set_time(1_800_000_000).unwrap();
    let failure = store.verify(der, &[]).unwrap_err();
    match failure {
        VerificationError::Untrusted(error) => {
            assert_ne!(error.code, 0);
            assert_eq!(error.certificate_der.unwrap(), der);
            assert!(!error.message.is_empty());
        }
        error => panic!("expected verification rejection: {error:?}"),
    }
    store
        .add_certificate_der(&cert.encode(Encoding::Der).unwrap())
        .unwrap();
    // Changing a caller-owned certificate must not mutate the installed anchor.
    cert.set_serial(&[0x42]).unwrap();
    let chain = store.verify(der, &[]).unwrap();
    assert_eq!(chain, vec![der.to_vec()]);
    drop(store);
    // Both chain and failure data remain usable after native owner destruction.
    assert_eq!(
        Certificate::decode(&chain[0], Encoding::Der)
            .unwrap()
            .encode(Encoding::Der)
            .unwrap(),
        der
    );
}
