// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! ML-DSA on verified-garbage (`verified_garbage::mldsa44`, `mldsa65`,
//! `mldsa87`). Private keys are kept as their 32-byte seed `xi`, the only
//! private key form cryptography supports; signing is hedged, as with
//! OpenSSL.

use pyo3::types::PyAnyMethods;

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};
use crate::exceptions;

const MAX_CONTEXT_BYTES: usize = 255;
const SEED_SIZE: usize = 32;
const MU_BYTES: usize = 64;

fn random_bytes<const N: usize>() -> CryptographyResult<[u8; N]> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf)
        .map_err(|_| CryptographyError::VerifiedGarbage("random number generator failed"))?;
    Ok(buf)
}

fn check_context<'a>(context: &'a Option<CffiBuf<'_>>) -> CryptographyResult<&'a [u8]> {
    let ctx_bytes = context.as_ref().map_or(&[][..], |c| c.as_bytes());
    if ctx_bytes.len() > MAX_CONTEXT_BYTES {
        return Err(CryptographyError::from(
            pyo3::exceptions::PyValueError::new_err("Context must be at most 255 bytes"),
        ));
    }
    Ok(ctx_bytes)
}

fn check_mu<'a>(mu: &'a CffiBuf<'_>) -> CryptographyResult<&'a [u8; MU_BYTES]> {
    mu.as_bytes().try_into().map_err(|_| {
        CryptographyError::from(pyo3::exceptions::PyValueError::new_err(
            "mu must be 64 bytes",
        ))
    })
}

fn invalid_signature() -> CryptographyError {
    CryptographyError::from(exceptions::InvalidSignature::new_err(()))
}

/// Defines the Python classes and functions of one ML-DSA parameter set.
macro_rules! ml_dsa {
    (
        name: $name:literal,
        vg: $vg:ident,
        signing_key: $SigningKey:ident,
        verifying_key: $VerifyingKey:ident,
        private_key: $PrivateKey:ident = $private_name:literal,
        public_key: $PublicKey:ident = $public_name:literal,
        raw: $Raw:ident,
        generate: $generate:ident,
        from_seed_bytes: $from_seed_bytes:ident,
        from_public_bytes: $from_public_bytes:ident,
        private_key_from_raw: $private_key_from_raw:ident,
        public_key_from_raw: $public_key_from_raw:ident,
        seed_error: $seed_error:literal,
        public_error: $public_error:literal,
    ) => {
        #[pyo3::pyclass(
                                    frozen,
                                    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
                                    name = $private_name
                                )]
        pub(crate) struct $PrivateKey {
            key: verified_garbage::$vg::$SigningKey,
        }

        #[pyo3::pyclass(
                                    frozen,
                                    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
                                    name = $public_name
                                )]
        pub(crate) struct $PublicKey {
            key: verified_garbage::$vg::$VerifyingKey,
        }

        /// The private key object of a seed.
        pub(crate) fn $private_key_from_raw(
            seed: &[u8; SEED_SIZE],
        ) -> CryptographyResult<$PrivateKey> {
            let key = verified_garbage::$vg::$SigningKey::from_seed(seed).map_err(|_| {
                CryptographyError::VerifiedGarbage(concat!($name, " key generation failed"))
            })?;
            Ok($PrivateKey { key })
        }

        /// The public key object of a public key's bytes: `ValueError` if it
        /// has the wrong length.
        pub(crate) fn $public_key_from_raw(data: &[u8]) -> CryptographyResult<$PublicKey> {
            let bytes = data
                .try_into()
                .map_err(|_| pyo3::exceptions::PyValueError::new_err($public_error))?;
            Ok($PublicKey {
                key: verified_garbage::$vg::$VerifyingKey::from_bytes(bytes),
            })
        }

        #[pyo3::pyfunction]
        fn $generate() -> CryptographyResult<$PrivateKey> {
            let mut seed = random_bytes::<SEED_SIZE>()?;
            let key = $private_key_from_raw(&seed);
            seed.fill(0);
            std::hint::black_box(&seed);
            key
        }

        #[pyo3::pyfunction]
        fn $from_seed_bytes(data: CffiBuf<'_>) -> CryptographyResult<$PrivateKey> {
            let seed: &[u8; SEED_SIZE] = data
                .as_bytes()
                .try_into()
                .map_err(|_| pyo3::exceptions::PyValueError::new_err($seed_error))?;
            $private_key_from_raw(seed)
        }

        #[pyo3::pyfunction]
        fn $from_public_bytes(data: CffiBuf<'_>) -> CryptographyResult<$PublicKey> {
            $public_key_from_raw(data.as_bytes())
        }

        impl $PrivateKey {
            fn raw(&self) -> cryptography_key_parsing::raw::PrivateKey {
                cryptography_key_parsing::raw::PrivateKey::$Raw(*self.key.seed())
            }
        }

        impl $PublicKey {
            fn raw(&self) -> cryptography_key_parsing::raw::PublicKey {
                cryptography_key_parsing::raw::PublicKey::$Raw(self.key.as_bytes().to_vec())
            }
        }

        #[pyo3::pymethods]
        impl $PrivateKey {
            #[pyo3(signature = (data, context=None))]
            fn sign<'p>(
                &self,
                py: pyo3::Python<'p>,
                data: CffiBuf<'_>,
                context: Option<CffiBuf<'_>>,
            ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
                let ctx_bytes = check_context(&context)?;
                let data_bytes = data.as_bytes();
                let sig = py
                    .detach(|| self.key.sign(data_bytes, ctx_bytes))
                    .map_err(|_| {
                        CryptographyError::VerifiedGarbage(concat!($name, " signing failed"))
                    })?;
                Ok(pyo3::types::PyBytes::new(py, &sig))
            }

            fn sign_mu<'p>(
                &self,
                py: pyo3::Python<'p>,
                mu: CffiBuf<'_>,
            ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
                let mu_bytes = check_mu(&mu)?;
                // Hedged `ML-DSA.Sign_internal` on the external mu, with fresh
                // randomness, as `ML-DSA.Sign` does (FIPS 204 Algorithm 2).
                let mut rnd = random_bytes::<32>()?;
                let sig = py.detach(|| self.key.sign_mu(mu_bytes, &rnd));
                rnd.fill(0);
                std::hint::black_box(&rnd);
                let sig = sig.map_err(|_| {
                    CryptographyError::VerifiedGarbage(concat!($name, " signing failed"))
                })?;
                Ok(pyo3::types::PyBytes::new(py, &sig))
            }

            fn public_key(&self) -> $PublicKey {
                $PublicKey {
                    key: self.key.verifying_key().clone(),
                }
            }

            fn private_bytes_raw<'p>(
                &self,
                py: pyo3::Python<'p>,
            ) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
                pyo3::types::PyBytes::new(py, self.key.seed())
            }

            fn private_bytes<'p>(
                slf: &pyo3::Bound<'p, Self>,
                py: pyo3::Python<'p>,
                encoding: crate::serialization::Encoding,
                format: crate::serialization::PrivateFormat,
                encryption_algorithm: &pyo3::Bound<'p, pyo3::PyAny>,
            ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
                // As with OpenSSL: Raw/Raw/NoEncryption is the seed, and any
                // other use of Raw goes down the non-raw path's errors.
                if encoding == crate::serialization::Encoding::Raw
                    && format == crate::serialization::PrivateFormat::Raw
                    && encryption_algorithm.is_instance(&crate::types::NO_ENCRYPTION.get(py)?)?
                {
                    return Ok(slf.get().private_bytes_raw(py));
                }
                utils::raw_private_bytes(
                    py,
                    slf,
                    &slf.get().raw(),
                    encoding,
                    format,
                    encryption_algorithm,
                    true,
                    false,
                )
            }

            fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
                slf
            }

            fn __deepcopy__<'p>(
                slf: pyo3::PyRef<'p, Self>,
                _memo: &pyo3::Bound<'p, pyo3::PyAny>,
            ) -> pyo3::PyRef<'p, Self> {
                slf
            }
        }

        #[pyo3::pymethods]
        impl $PublicKey {
            fn verify_mu(
                &self,
                py: pyo3::Python<'_>,
                signature: CffiBuf<'_>,
                mu: CffiBuf<'_>,
            ) -> CryptographyResult<()> {
                let mu_bytes = check_mu(&mu)?;
                let sig: &[u8; verified_garbage::$vg::$VerifyingKey::SIGNATURE_SIZE] = signature
                    .as_bytes()
                    .try_into()
                    .map_err(|_| invalid_signature())?;
                py.detach(|| self.key.verify_mu(mu_bytes, sig))
                    .map_err(|_| invalid_signature())
            }

            #[pyo3(signature = (signature, data, context=None))]
            fn verify(
                &self,
                py: pyo3::Python<'_>,
                signature: CffiBuf<'_>,
                data: CffiBuf<'_>,
                context: Option<CffiBuf<'_>>,
            ) -> CryptographyResult<()> {
                let ctx_bytes = check_context(&context)?;
                let sig: &[u8; verified_garbage::$vg::$VerifyingKey::SIGNATURE_SIZE] = signature
                    .as_bytes()
                    .try_into()
                    .map_err(|_| invalid_signature())?;
                let data_bytes = data.as_bytes();
                py.detach(|| self.key.verify(data_bytes, ctx_bytes, sig))
                    .map_err(|_| invalid_signature())
            }

            fn public_bytes_raw<'p>(
                &self,
                py: pyo3::Python<'p>,
            ) -> pyo3::Bound<'p, pyo3::types::PyBytes> {
                pyo3::types::PyBytes::new(py, self.key.as_bytes())
            }

            fn public_bytes<'p>(
                slf: &pyo3::Bound<'p, Self>,
                py: pyo3::Python<'p>,
                encoding: crate::serialization::Encoding,
                format: crate::serialization::PublicFormat,
            ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
                utils::raw_public_bytes(py, slf, &slf.get().raw(), encoding, format, true, true)
            }

            fn __eq__(&self, other: pyo3::PyRef<'_, Self>) -> bool {
                self.key.as_bytes() == other.key.as_bytes()
            }

            fn __copy__(slf: pyo3::PyRef<'_, Self>) -> pyo3::PyRef<'_, Self> {
                slf
            }

            fn __deepcopy__<'p>(
                slf: pyo3::PyRef<'p, Self>,
                _memo: &pyo3::Bound<'p, pyo3::PyAny>,
            ) -> pyo3::PyRef<'p, Self> {
                slf
            }
        }
    };
}

ml_dsa! {
    name: "ML-DSA-44",
    vg: mldsa44,
    signing_key: SigningKey44,
    verifying_key: VerifyingKey44,
    private_key: MlDsa44PrivateKey = "MLDSA44PrivateKey",
    public_key: MlDsa44PublicKey = "MLDSA44PublicKey",
    raw: MlDsa44,
    generate: generate_mldsa44_key,
    from_seed_bytes: from_mldsa44_seed_bytes,
    from_public_bytes: from_mldsa44_public_bytes,
    private_key_from_raw: mldsa44_private_key_from_raw,
    public_key_from_raw: mldsa44_public_key_from_raw,
    seed_error: "An ML-DSA-44 seed is 32 bytes long",
    public_error: "An ML-DSA-44 public key is 1312 bytes long",
}

ml_dsa! {
    name: "ML-DSA-65",
    vg: mldsa65,
    signing_key: SigningKey65,
    verifying_key: VerifyingKey65,
    private_key: MlDsa65PrivateKey = "MLDSA65PrivateKey",
    public_key: MlDsa65PublicKey = "MLDSA65PublicKey",
    raw: MlDsa65,
    generate: generate_mldsa65_key,
    from_seed_bytes: from_mldsa65_seed_bytes,
    from_public_bytes: from_mldsa65_public_bytes,
    private_key_from_raw: mldsa65_private_key_from_raw,
    public_key_from_raw: mldsa65_public_key_from_raw,
    seed_error: "An ML-DSA-65 seed is 32 bytes long",
    public_error: "An ML-DSA-65 public key is 1952 bytes long",
}

ml_dsa! {
    name: "ML-DSA-87",
    vg: mldsa87,
    signing_key: SigningKey87,
    verifying_key: VerifyingKey87,
    private_key: MlDsa87PrivateKey = "MLDSA87PrivateKey",
    public_key: MlDsa87PublicKey = "MLDSA87PublicKey",
    raw: MlDsa87,
    generate: generate_mldsa87_key,
    from_seed_bytes: from_mldsa87_seed_bytes,
    from_public_bytes: from_mldsa87_public_bytes,
    private_key_from_raw: mldsa87_private_key_from_raw,
    public_key_from_raw: mldsa87_public_key_from_raw,
    seed_error: "An ML-DSA-87 seed is 32 bytes long",
    public_error: "An ML-DSA-87 public key is 2592 bytes long",
}

/// The raw public key bytes of any ML-DSA public key object.
fn mldsa_public_key_raw(public_key: &pyo3::Bound<'_, pyo3::PyAny>) -> CryptographyResult<Vec<u8>> {
    if let Ok(k) = public_key.cast::<MlDsa44PublicKey>() {
        Ok(k.get().key.as_bytes().to_vec())
    } else if let Ok(k) = public_key.cast::<MlDsa65PublicKey>() {
        Ok(k.get().key.as_bytes().to_vec())
    } else if let Ok(k) = public_key.cast::<MlDsa87PublicKey>() {
        Ok(k.get().key.as_bytes().to_vec())
    } else {
        Err(CryptographyError::from(
            pyo3::exceptions::PyTypeError::new_err("public_key must be an ML-DSA public key."),
        ))
    }
}

/// A SHAKE256 hasher pre-loaded with the fixed part of the pure-ML-DSA mu
/// input: `SHAKE256(pk, 64) || 0x00 || len(ctx) || ctx` (FIPS 204
/// Algorithms 2 and 7). The message is absorbed later by
/// [`MlDsaMuHasher::update`].
fn mu_hasher_init(
    raw_pk: &[u8],
    context: &[u8],
) -> CryptographyResult<cryptography_crypto::hash::Hasher> {
    use cryptography_crypto::hash::{Hasher, MessageDigest};
    // tr = SHAKE256(pk, 64)
    let mut tr = [0u8; MU_BYTES];
    let mut h = Hasher::new(MessageDigest::Shake256)?;
    h.update(raw_pk)?;
    h.finish_xof(&mut tr)?;
    let mut ctx = Hasher::new(MessageDigest::Shake256)?;
    ctx.update(&tr)?;
    // Pure-ML-DSA M' prefix: domain separator 0x00, then the context.
    ctx.update(&[0x00, context.len() as u8])?;
    ctx.update(context)?;
    Ok(ctx)
}

#[pyo3::pyclass(
    module = "cryptography.hazmat.bindings._rust.openssl.mldsa",
    name = "MLDSAMuHasher"
)]
pub(crate) struct MlDsaMuHasher {
    ctx: Option<cryptography_crypto::hash::Hasher>,
}

impl MlDsaMuHasher {
    fn get_mut_ctx(&mut self) -> CryptographyResult<&mut cryptography_crypto::hash::Hasher> {
        if let Some(ctx) = self.ctx.as_mut() {
            return Ok(ctx);
        }
        Err(exceptions::already_finalized_error())
    }

    fn get_ctx(&self) -> CryptographyResult<&cryptography_crypto::hash::Hasher> {
        if let Some(ctx) = self.ctx.as_ref() {
            return Ok(ctx);
        }
        Err(exceptions::already_finalized_error())
    }
}

#[pyo3::pymethods]
impl MlDsaMuHasher {
    #[new]
    #[pyo3(signature = (public_key, context=None))]
    fn new(
        public_key: &pyo3::Bound<'_, pyo3::PyAny>,
        context: Option<CffiBuf<'_>>,
    ) -> CryptographyResult<MlDsaMuHasher> {
        let ctx_bytes = check_context(&context)?;
        let raw_pk = mldsa_public_key_raw(public_key)?;
        Ok(MlDsaMuHasher {
            ctx: Some(mu_hasher_init(&raw_pk, ctx_bytes)?),
        })
    }

    fn update(&mut self, data: CffiBuf<'_>) -> CryptographyResult<()> {
        self.get_mut_ctx()?.update(data.as_bytes())?;
        Ok(())
    }

    fn copy(&self) -> CryptographyResult<MlDsaMuHasher> {
        Ok(MlDsaMuHasher {
            ctx: Some(self.get_ctx()?.clone()),
        })
    }

    fn finalize<'p>(
        &mut self,
        py: pyo3::Python<'p>,
    ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
        let ctx = self.get_mut_ctx()?;
        let mut mu = [0u8; MU_BYTES];
        ctx.finish_xof(&mut mu)?;
        self.ctx = None;
        Ok(pyo3::types::PyBytes::new(py, &mu))
    }
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod mldsa {
    #[pymodule_export]
    use super::{
        from_mldsa44_public_bytes, from_mldsa44_seed_bytes, from_mldsa65_public_bytes,
        from_mldsa65_seed_bytes, from_mldsa87_public_bytes, from_mldsa87_seed_bytes,
        generate_mldsa44_key, generate_mldsa65_key, generate_mldsa87_key, MlDsa44PrivateKey,
        MlDsa44PublicKey, MlDsa65PrivateKey, MlDsa65PublicKey, MlDsa87PrivateKey, MlDsa87PublicKey,
        MlDsaMuHasher,
    };
}

#[cfg(test)]
mod tests {
    use pyo3::types::PyBytesMethods;

    use super::MlDsaMuHasher;
    use crate::backend::vg_test_vectors::{load_nist_vectors, read, unhex, Check};
    use crate::buf::CffiBuf;

    macro_rules! kat_test {
        (
            $test:ident, $file:literal, $sig_len:literal,
            $generate:ident, $from_seed:ident, $from_public:ident
        ) => {
            #[test]
            fn $test() {
                pyo3::Python::initialize();
                pyo3::Python::attach(|py| {
                    let data = read(concat!("asymmetric/MLDSA/", $file));
                    let vectors = load_nist_vectors(&data, 10);
                    assert_eq!(vectors.len(), 10);
                    for vector in &vectors {
                        let xi = unhex(&vector["xi"]);
                        let pk = unhex(&vector["pk"]);
                        let msg = unhex(&vector["msg"]);
                        let ctx = unhex(&vector["ctx"]);
                        let sig = unhex(&vector["sm"])[..$sig_len].to_vec();

                        let key = super::$from_seed(CffiBuf::from_bytes(py, &xi)).check();
                        assert_eq!(key.private_bytes_raw(py).as_bytes(), &xi[..]);
                        assert_eq!(key.public_key().public_bytes_raw(py).as_bytes(), &pk[..]);

                        let public = super::$from_public(CffiBuf::from_bytes(py, &pk)).check();
                        let verify = |sig: &[u8], msg: &[u8], ctx: &[u8]| {
                            public.verify(
                                py,
                                CffiBuf::from_bytes(py, sig),
                                CffiBuf::from_bytes(py, msg),
                                Some(CffiBuf::from_bytes(py, ctx)),
                            )
                        };
                        verify(&sig, &msg, &ctx).check();
                        let mut bad = msg.clone();
                        bad.push(0);
                        assert!(verify(&sig, &bad, &ctx).is_err());
                        assert!(verify(&sig[1..], &msg, &ctx).is_err());

                        // mu, computed by the hasher, verifies the signature.
                        let public_obj = pyo3::Bound::new(py, public).check();
                        let mut hasher = MlDsaMuHasher::new(
                            public_obj.as_any(),
                            Some(CffiBuf::from_bytes(py, &ctx)),
                        )
                        .check();
                        hasher.update(CffiBuf::from_bytes(py, &msg)).check();
                        let mut copy = hasher.copy().check();
                        let mu = hasher.finalize(py).check();
                        assert!(hasher.update(CffiBuf::from_bytes(py, &msg)).is_err());
                        assert_eq!(copy.finalize(py).check().as_bytes(), mu.as_bytes());
                        let public = public_obj.get();
                        public
                            .verify_mu(
                                py,
                                CffiBuf::from_bytes(py, &sig),
                                CffiBuf::from_bytes(py, mu.as_bytes()),
                            )
                            .check();
                        let mut wrong_mu = mu.as_bytes().to_vec();
                        wrong_mu[0] ^= 1;
                        assert!(public
                            .verify_mu(
                                py,
                                CffiBuf::from_bytes(py, &sig),
                                CffiBuf::from_bytes(py, &wrong_mu),
                            )
                            .is_err());

                        // Hedged signatures of the message and of mu verify.
                        let sig = key
                            .sign(
                                py,
                                CffiBuf::from_bytes(py, &msg),
                                Some(CffiBuf::from_bytes(py, &ctx)),
                            )
                            .check();
                        public
                            .verify(
                                py,
                                CffiBuf::from_bytes(py, sig.as_bytes()),
                                CffiBuf::from_bytes(py, &msg),
                                Some(CffiBuf::from_bytes(py, &ctx)),
                            )
                            .check();
                        let sig = key
                            .sign_mu(py, CffiBuf::from_bytes(py, mu.as_bytes()))
                            .check();
                        public
                            .verify(
                                py,
                                CffiBuf::from_bytes(py, sig.as_bytes()),
                                CffiBuf::from_bytes(py, &msg),
                                Some(CffiBuf::from_bytes(py, &ctx)),
                            )
                            .check();
                    }

                    let key = super::$generate().check();
                    assert!(key
                        .sign(
                            py,
                            CffiBuf::from_bytes(py, b"m"),
                            Some(CffiBuf::from_bytes(py, &[0; 256])),
                        )
                        .is_err());
                    assert!(key.sign_mu(py, CffiBuf::from_bytes(py, &[0; 63])).is_err());
                    assert!(super::$from_seed(CffiBuf::from_bytes(py, &[0; 31])).is_err());
                    assert!(super::$from_public(CffiBuf::from_bytes(py, &[0; 10])).is_err());
                });
            }
        };
    }

    kat_test!(
        test_mldsa44_kat,
        "kat_MLDSA_44_det_pure.rsp",
        2420,
        generate_mldsa44_key,
        from_mldsa44_seed_bytes,
        from_mldsa44_public_bytes
    );
    kat_test!(
        test_mldsa65_kat,
        "kat_MLDSA_65_det_pure.rsp",
        3309,
        generate_mldsa65_key,
        from_mldsa65_seed_bytes,
        from_mldsa65_public_bytes
    );
    kat_test!(
        test_mldsa87_kat,
        "kat_MLDSA_87_det_pure.rsp",
        4627,
        generate_mldsa87_key,
        from_mldsa87_seed_bytes,
        from_mldsa87_public_bytes
    );
}
