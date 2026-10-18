// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

//! ML-KEM on verified-garbage (`verified_garbage::mlkem768`,
//! `verified_garbage::mlkem1024`). Private keys are kept as their 64-byte
//! seed `d || z`, the only private key form cryptography supports.

use pyo3::types::PyAnyMethods;

use crate::backend::utils;
use crate::buf::CffiBuf;
use crate::error::{CryptographyError, CryptographyResult};

const SEED_SIZE: usize = 64;

/// Defines the Python classes and functions of one ML-KEM parameter set.
macro_rules! ml_kem {
    (
        name: $name:literal,
        vg: $vg:ident,
        decapsulation_key: $DecapsulationKey:ident,
        encapsulation_key: $EncapsulationKey:ident,
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
        ciphertext_error: $ciphertext_error:literal,
        encapsulation_error: $encapsulation_error:literal,
    ) => {
        #[pyo3::pyclass(
                                    frozen,
                                    module = "cryptography.hazmat.bindings._rust.openssl.mlkem",
                                    name = $private_name
                                )]
        pub(crate) struct $PrivateKey {
            key: verified_garbage::$vg::$DecapsulationKey,
        }

        #[pyo3::pyclass(
                                    frozen,
                                    module = "cryptography.hazmat.bindings._rust.openssl.mlkem",
                                    name = $public_name
                                )]
        pub(crate) struct $PublicKey {
            key: verified_garbage::$vg::$EncapsulationKey,
        }

        /// The private key object of a seed.
        pub(crate) fn $private_key_from_raw(
            seed: &[u8; SEED_SIZE],
        ) -> CryptographyResult<$PrivateKey> {
            let key = verified_garbage::$vg::$DecapsulationKey::from_seed(seed).map_err(|_| {
                CryptographyError::VerifiedGarbage(concat!($name, " key generation failed"))
            })?;
            Ok($PrivateKey { key })
        }

        /// The public key object of an encapsulation key: `ValueError` if it
        /// has the wrong length or fails the check of FIPS 203 §7.2 (as
        /// OpenSSL does).
        pub(crate) fn $public_key_from_raw(data: &[u8]) -> CryptographyResult<$PublicKey> {
            let key = data
                .try_into()
                .ok()
                .and_then(|bytes| verified_garbage::$vg::$EncapsulationKey::from_bytes(bytes).ok())
                .ok_or_else(|| pyo3::exceptions::PyValueError::new_err($public_error))?;
            Ok($PublicKey { key })
        }

        #[pyo3::pyfunction]
        fn $generate() -> CryptographyResult<$PrivateKey> {
            let mut seed = [0u8; SEED_SIZE];
            getrandom::fill(&mut seed).map_err(|_| {
                CryptographyError::VerifiedGarbage("random number generator failed")
            })?;
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
            fn decapsulate<'p>(
                &self,
                py: pyo3::Python<'p>,
                ciphertext: CffiBuf<'_>,
            ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyBytes>> {
                let shared_secret = ciphertext
                    .as_bytes()
                    .try_into()
                    .ok()
                    .and_then(|ct| self.key.decapsulate(ct).ok())
                    .ok_or_else(|| pyo3::exceptions::PyValueError::new_err($ciphertext_error))?;
                Ok(pyo3::types::PyBytes::new(py, &shared_secret))
            }

            fn public_key(&self) -> $PublicKey {
                $PublicKey {
                    key: self.key.encapsulation_key().clone(),
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
            fn encapsulate<'p>(
                &self,
                py: pyo3::Python<'p>,
            ) -> CryptographyResult<pyo3::Bound<'p, pyo3::types::PyTuple>> {
                let (shared_secret, ciphertext) = self
                    .key
                    .encapsulate()
                    .map_err(|_| pyo3::exceptions::PyValueError::new_err($encapsulation_error))?;
                let ss = pyo3::types::PyBytes::new(py, &shared_secret);
                let ct = pyo3::types::PyBytes::new(py, &ciphertext);
                Ok(pyo3::types::PyTuple::new(py, [ss.as_any(), ct.as_any()])?)
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
                self.key == other.key
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

ml_kem! {
    name: "ML-KEM-768",
    vg: mlkem768,
    decapsulation_key: DecapsulationKey768,
    encapsulation_key: EncapsulationKey768,
    private_key: MlKem768PrivateKey = "MLKEM768PrivateKey",
    public_key: MlKem768PublicKey = "MLKEM768PublicKey",
    raw: MlKem768,
    generate: generate_mlkem768_key,
    from_seed_bytes: from_mlkem768_seed_bytes,
    from_public_bytes: from_mlkem768_public_bytes,
    private_key_from_raw: mlkem768_private_key_from_raw,
    public_key_from_raw: mlkem768_public_key_from_raw,
    seed_error: "An ML-KEM-768 seed is 64 bytes long",
    public_error: "An ML-KEM-768 public key is 1184 bytes long",
    ciphertext_error: "Invalid ML-KEM-768 ciphertext",
    encapsulation_error: "ML-KEM-768 encapsulation failed",
}

ml_kem! {
    name: "ML-KEM-1024",
    vg: mlkem1024,
    decapsulation_key: DecapsulationKey1024,
    encapsulation_key: EncapsulationKey1024,
    private_key: MlKem1024PrivateKey = "MLKEM1024PrivateKey",
    public_key: MlKem1024PublicKey = "MLKEM1024PublicKey",
    raw: MlKem1024,
    generate: generate_mlkem1024_key,
    from_seed_bytes: from_mlkem1024_seed_bytes,
    from_public_bytes: from_mlkem1024_public_bytes,
    private_key_from_raw: mlkem1024_private_key_from_raw,
    public_key_from_raw: mlkem1024_public_key_from_raw,
    seed_error: "An ML-KEM-1024 seed is 64 bytes long",
    public_error: "An ML-KEM-1024 public key is 1568 bytes long",
    ciphertext_error: "Invalid ML-KEM-1024 ciphertext",
    encapsulation_error: "ML-KEM-1024 encapsulation failed",
}

#[pyo3::pymodule(gil_used = false)]
pub(crate) mod mlkem {
    #[pymodule_export]
    use super::{
        from_mlkem1024_public_bytes, from_mlkem1024_seed_bytes, from_mlkem768_public_bytes,
        from_mlkem768_seed_bytes, generate_mlkem1024_key, generate_mlkem768_key,
        MlKem1024PrivateKey, MlKem1024PublicKey, MlKem768PrivateKey, MlKem768PublicKey,
    };
}

#[cfg(test)]
mod tests {
    use pyo3::types::{PyBytesMethods, PyTupleMethods};

    use crate::backend::vg_test_vectors::{load_nist_vectors, read, unhex, Check};
    use crate::buf::CffiBuf;

    macro_rules! kat_test {
        ($test:ident, $file:literal, $generate:ident, $from_seed:ident, $from_public:ident) => {
            #[test]
            fn $test() {
                pyo3::Python::initialize();
                pyo3::Python::attach(|py| {
                    let data = read(concat!("asymmetric/MLKEM/", $file));
                    let vectors = load_nist_vectors(&data, 10);
                    assert_eq!(vectors.len(), 10);
                    for vector in &vectors {
                        let mut seed = unhex(&vector["d"]);
                        seed.extend(unhex(&vector["z"]));
                        let pk = unhex(&vector["pk"]);
                        let key = super::$from_seed(CffiBuf::from_bytes(py, &seed)).check();
                        assert_eq!(key.private_bytes_raw(py).as_bytes(), &seed[..]);
                        let public = key.public_key();
                        assert_eq!(public.public_bytes_raw(py).as_bytes(), &pk[..]);
                        let loaded = super::$from_public(CffiBuf::from_bytes(py, &pk)).check();
                        assert!(loaded.__eq__(pyo3::Py::new(py, public).check().borrow(py)));

                        // The ciphertext of the KAT, and the implicit rejection
                        // of a modified one.
                        for (ct, ss) in [("ct", "ss"), ("ct_n", "ss_n")] {
                            let ct = unhex(&vector[ct]);
                            let ss = unhex(&vector[ss]);
                            let got = key.decapsulate(py, CffiBuf::from_bytes(py, &ct)).check();
                            assert_eq!(got.as_bytes(), &ss[..]);
                        }
                        let ct = unhex(&vector["ct"]);
                        assert!(key
                            .decapsulate(py, CffiBuf::from_bytes(py, &ct[1..]))
                            .is_err());

                        let pair = loaded.encapsulate(py).check();
                        let ss = pair.get_item(0).check();
                        let ct = pair.get_item(1).check();
                        let ct = ct.cast::<pyo3::types::PyBytes>().check();
                        let got = key
                            .decapsulate(py, CffiBuf::from_bytes(py, ct.as_bytes()))
                            .check();
                        assert_eq!(
                            got.as_bytes(),
                            ss.cast::<pyo3::types::PyBytes>().check().as_bytes()
                        );
                    }

                    assert!(super::$generate().is_ok());
                    assert!(super::$from_seed(CffiBuf::from_bytes(py, &[0; 63])).is_err());
                    assert!(super::$from_public(CffiBuf::from_bytes(py, &[0; 10])).is_err());
                    // Every 12-bit coefficient 0xfff is at least q: the key
                    // fails the check of FIPS 203 §7.2.
                    let pk = unhex(&vectors[0]["pk"]);
                    let bad = vec![0xff; pk.len()];
                    assert!(super::$from_public(CffiBuf::from_bytes(py, &bad)).is_err());
                });
            }
        };
    }

    kat_test!(
        test_mlkem768_kat,
        "kat_MLKEM_768.rsp",
        generate_mlkem768_key,
        from_mlkem768_seed_bytes,
        from_mlkem768_public_bytes
    );
    kat_test!(
        test_mlkem1024_kat,
        "kat_MLKEM_1024.rsp",
        generate_mlkem1024_key,
        from_mlkem1024_seed_bytes,
        from_mlkem1024_public_bytes
    );
}
