//! Algorithm-specific owned keys and borrowed serialization views.
use openssl_bridge as bridge;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structured_keys_reject_raw_serialization() {
        let key = bridge::ec::PrivateKey::generate(bridge::ec::Curve::P256).unwrap();
        assert!(PrivateKeyRef::Ec(&key).raw_bytes().is_err());
        assert!(PublicKeyRef::Ec(&key.public_key().unwrap())
            .raw_bytes()
            .is_err());
    }

    #[cfg(any(
        CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    ))]
    #[test]
    fn post_quantum_raw_encodings_preserve_seeds_and_public_keys() {
        let dsa =
            bridge::mldsa::PrivateKey::from_seed(bridge::mldsa::Variant::MlDsa44, &[0x42; 32])
                .unwrap();
        assert_eq!(
            PrivateKeyRef::MlDsa(&dsa).raw_bytes().unwrap().as_ref(),
            &[0x42; 32]
        );
        let public = dsa.public_key();
        assert_eq!(
            PublicKeyRef::MlDsa(&public).raw_bytes().unwrap(),
            public.as_bytes()
        );
        let kem =
            bridge::mlkem::PrivateKey::from_seed(bridge::mlkem::Variant::MlKem768, &[0x24; 64])
                .unwrap();
        assert_eq!(
            PrivateKeyRef::MlKem(&kem).raw_bytes().unwrap().as_ref(),
            &[0x24; 64]
        );
        let public = kem.public_key();
        assert_eq!(
            PublicKeyRef::MlKem(&public).raw_bytes().unwrap(),
            public.as_bytes()
        );
    }
}
pub enum ParsedPrivateKey {
    Rsa(crate::rsa::RsaPrivateMaterial),
    Ec(bridge::ec::PrivateKey),
    Dsa(bridge::dsa::PrivateKeyMaterial),
    Dh(bridge::dh::PrivateKeyMaterial),
    Ed25519(bridge::curve25519::Ed25519SigningKey),
    X25519(bridge::curve25519::X25519SecretKey),
    #[cfg(not(any(
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    )))]
    Ed448(bridge::curve448::Ed448SigningKey),
    #[cfg(not(any(
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    )))]
    X448(bridge::curve448::X448SecretKey),
    #[cfg(any(
        CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    ))]
    MlDsa(bridge::mldsa::PrivateKey),
    #[cfg(any(
        CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    ))]
    MlKem(bridge::mlkem::PrivateKey),
}
#[derive(Clone, Copy)]
pub enum PrivateKeyRef<'a> {
    Rsa(bridge::rsa::PrivateComponents<'a>),
    Ec(&'a bridge::ec::PrivateKey),
    Dsa(&'a bridge::dsa::PrivateKeyMaterial),
    Dh(&'a bridge::dh::PrivateKeyMaterial),
    Ed25519(&'a bridge::curve25519::Ed25519SigningKey),
    X25519(&'a bridge::curve25519::X25519SecretKey),
    #[cfg(not(any(
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    )))]
    Ed448(&'a bridge::curve448::Ed448SigningKey),
    #[cfg(not(any(
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    )))]
    X448(&'a bridge::curve448::X448SecretKey),
    #[cfg(any(
        CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    ))]
    MlDsa(&'a bridge::mldsa::PrivateKey),
    #[cfg(any(
        CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    ))]
    MlKem(&'a bridge::mlkem::PrivateKey),
}
pub enum ParsedPublicKey {
    Rsa(bridge::rsa::PublicKey),
    Ec(bridge::ec::PublicKey),
    Dsa(bridge::dsa::PublicKeyMaterial),
    Dh(bridge::dh::PublicKeyMaterial),
    Ed25519(bridge::curve25519::Ed25519VerifyingKey),
    X25519(bridge::curve25519::X25519PublicKey),
    #[cfg(not(any(
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    )))]
    Ed448(bridge::curve448::Ed448VerifyingKey),
    #[cfg(not(any(
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    )))]
    X448(bridge::curve448::X448PublicKey),
    #[cfg(any(
        CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    ))]
    MlDsa(bridge::mldsa::PublicKey),
    #[cfg(any(
        CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    ))]
    MlKem(bridge::mlkem::PublicKey),
}
#[derive(Clone, Copy)]
pub enum PublicKeyRef<'a> {
    Rsa(&'a bridge::rsa::PublicKey),
    Ec(&'a bridge::ec::PublicKey),
    Dsa(&'a bridge::dsa::PublicKeyMaterial),
    Dh(&'a bridge::dh::PublicKeyMaterial),
    Ed25519(&'a bridge::curve25519::Ed25519VerifyingKey),
    X25519(&'a bridge::curve25519::X25519PublicKey),
    #[cfg(not(any(
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    )))]
    Ed448(&'a bridge::curve448::Ed448VerifyingKey),
    #[cfg(not(any(
        CRYPTOGRAPHY_IS_LIBRESSL,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    )))]
    X448(&'a bridge::curve448::X448PublicKey),
    #[cfg(any(
        CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    ))]
    MlDsa(&'a bridge::mldsa::PublicKey),
    #[cfg(any(
        CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    ))]
    MlKem(&'a bridge::mlkem::PublicKey),
}
impl ParsedPublicKey {
    pub fn as_key_ref(&self) -> PublicKeyRef<'_> {
        match self {
            Self::Rsa(key) => PublicKeyRef::Rsa(key),
            Self::Ec(key) => PublicKeyRef::Ec(key),
            Self::Dsa(key) => PublicKeyRef::Dsa(key),
            Self::Dh(key) => PublicKeyRef::Dh(key),
            Self::Ed25519(key) => PublicKeyRef::Ed25519(key),
            Self::X25519(key) => PublicKeyRef::X25519(key),
            #[cfg(not(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            )))]
            Self::Ed448(key) => PublicKeyRef::Ed448(key),
            #[cfg(not(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            )))]
            Self::X448(key) => PublicKeyRef::X448(key),
            #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            ))]
            Self::MlDsa(key) => PublicKeyRef::MlDsa(key),
            #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            ))]
            Self::MlKem(key) => PublicKeyRef::MlKem(key),
        }
    }
}

impl ParsedPrivateKey {
    pub fn public_key(&self) -> openssl_bridge::Result<ParsedPublicKey> {
        Ok(match self {
            Self::Rsa(key) => {
                let parts = key.components();
                ParsedPublicKey::Rsa(bridge::rsa::PublicKey::from_components(parts.n, parts.e)?)
            }
            Self::Ec(key) => ParsedPublicKey::Ec(key.public_key()?),
            Self::Dsa(key) => ParsedPublicKey::Dsa(key.public_key()),
            Self::Dh(key) => ParsedPublicKey::Dh(key.public_key()),
            Self::Ed25519(key) => ParsedPublicKey::Ed25519(key.verifying_key()?),
            Self::X25519(key) => ParsedPublicKey::X25519(key.public_key()?),
            #[cfg(not(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            )))]
            Self::Ed448(key) => ParsedPublicKey::Ed448(key.verifying_key()?),
            #[cfg(not(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            )))]
            Self::X448(key) => ParsedPublicKey::X448(key.public_key()?),
            #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            ))]
            Self::MlDsa(key) => ParsedPublicKey::MlDsa(key.public_key()),
            #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            ))]
            Self::MlKem(key) => ParsedPublicKey::MlKem(key.public_key()),
        })
    }
}

impl PrivateKeyRef<'_> {
    pub fn raw_bytes(self) -> bridge::Result<bridge::secret::SecretBytes> {
        let bytes = match self {
            Self::Ed25519(key) => key.to_seed()?.as_ref().to_vec(),
            Self::X25519(key) => key.to_bytes()?.as_ref().to_vec(),
            #[cfg(not(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            )))]
            Self::Ed448(key) => key.to_seed()?.as_ref().to_vec(),
            #[cfg(not(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            )))]
            Self::X448(key) => key.to_bytes()?.as_ref().to_vec(),
            #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            ))]
            Self::MlDsa(key) => key.seed().to_vec(),
            #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            ))]
            Self::MlKem(key) => key.seed().to_vec(),
            _ => {
                return Err(bridge::Error::Unsupported(
                    "key has no raw private encoding",
                ))
            }
        };
        Ok(bytes.into())
    }
}
impl PublicKeyRef<'_> {
    pub fn raw_bytes(self) -> bridge::Result<Vec<u8>> {
        Ok(match self {
            Self::Ed25519(key) => key.to_bytes()?.to_vec(),
            Self::X25519(key) => key.to_bytes()?.to_vec(),
            #[cfg(not(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            )))]
            Self::Ed448(key) => key.to_bytes()?.to_vec(),
            #[cfg(not(any(
                CRYPTOGRAPHY_IS_LIBRESSL,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            )))]
            Self::X448(key) => key.to_bytes()?.to_vec(),
            #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            ))]
            Self::MlDsa(key) => key.as_bytes().to_vec(),
            #[cfg(any(
                CRYPTOGRAPHY_OPENSSL_350_OR_GREATER,
                CRYPTOGRAPHY_IS_BORINGSSL,
                CRYPTOGRAPHY_IS_AWSLC
            ))]
            Self::MlKem(key) => key.as_bytes().to_vec(),
            _ => return Err(bridge::Error::Unsupported("key has no raw public encoding")),
        })
    }
}
