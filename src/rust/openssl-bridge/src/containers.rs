//! Narrow compatibility decoders for legacy certificate containers.
//!
//! Native objects never escape a call. Results own their DER bytes, and private
//! key bytes are erased on drop. Decoding a certificate does not verify trust;
//! decoding a private key does not grant permission to use it without validation.
use crate::{error::pointer, ffi, secret::SecretBytes, Error, Result};
use std::{ffi::CStr, ptr};

pub struct Certificate {
    pub der: Vec<u8>,
    pub alias: Option<Vec<u8>>,
}

pub struct ParsedPkcs12 {
    pub private_key: Option<SecretBytes>,
    pub certificate: Option<Certificate>,
    /// The selected backend's order. LibreSSL historically reverses this list.
    pub additional_certificates: Vec<Certificate>,
}

#[derive(Debug)]
pub enum Pkcs12Error {
    Encoding(Error),
    PasswordOrData(Error),
    Output(Error),
}
impl std::fmt::Display for Pkcs12Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encoding(e) => write!(f, "invalid PKCS#12 encoding: {e}"),
            Self::PasswordOrData(e) => write!(f, "invalid PKCS#12 password or data: {e}"),
            Self::Output(e) => write!(f, "PKCS#12 export failed: {e}"),
        }
    }
}
impl std::error::Error for Pkcs12Error {}

struct NativePkcs12(*mut ffi::PKCS12);
impl Drop for NativePkcs12 {
    fn drop(&mut self) {
        // SAFETY: Sole ownership, obtained from d2i_PKCS12.
        unsafe { ffi::PKCS12_free(self.0) };
    }
}
struct NativeParts {
    key: *mut ffi::EVP_PKEY,
    cert: *mut ffi::X509,
    ca: *mut ffi::stack_st_X509,
}
impl Drop for NativeParts {
    fn drop(&mut self) {
        // SAFETY: PKCS12_parse transfers each non-null output to the caller,
        // including a partially populated CA stack on failure. These frees
        // accept NULL. The matching certificate is removed from the CA stack.
        unsafe {
            ffi::EVP_PKEY_free(self.key);
            ffi::X509_free(self.cert);
            ffi::OB_x509_stack_free(self.ca);
        }
    }
}
#[cfg(any(backend = "openssl", backend = "libressl"))]
struct NativePkcs8(*mut ffi::PKCS8_PRIV_KEY_INFO);
#[cfg(any(backend = "openssl", backend = "libressl"))]
impl Drop for NativePkcs8 {
    fn drop(&mut self) {
        // SAFETY: Sole ownership from EVP_PKEY2PKCS8. OpenSSL and LibreSSL
        // cleanse the private key octet string in their ASN.1 free callback.
        unsafe { ffi::PKCS8_PRIV_KEY_INFO_free(self.0) };
    }
}

/// Decode a legacy PKCS#12 container, including the backend's BER compatibility.
///
/// `password` is NUL-free and terminated by construction. NULL and an empty
/// password are interpreted according to the selected backend's PKCS#12 rules.
/// No reference to either input is retained. Native KDF work is synchronous.
/// BoringSSL and AWS-LC private-key DER exports are limited to 16 MiB.
pub fn parse_pkcs12(
    data: &[u8],
    password: Option<&CStr>,
) -> std::result::Result<ParsedPkcs12, Pkcs12Error> {
    crate::initialize().map_err(Pkcs12Error::Encoding)?;
    // The d2i length is long on OpenSSL, but size_t on BoringSSL.
    #[allow(clippy::useless_conversion)]
    let length = data
        .len()
        .try_into()
        .map_err(|_| Pkcs12Error::Encoding(Error::InvalidInput("PKCS#12 input is too long")))?;
    let mut cursor = data.as_ptr();
    let p12 = NativePkcs12(
        // SAFETY: The decoder reads at most length bytes; NULL requests a fresh
        // object. It may accept trailing bytes, matching native BER compatibility.
        pointer(unsafe { ffi::d2i_PKCS12(ptr::null_mut(), &mut cursor, length) })
            .map_err(Pkcs12Error::Encoding)?
            .as_ptr(),
    );
    let mut parts = NativeParts {
        key: ptr::null_mut(),
        cert: ptr::null_mut(),
        ca: ptr::null_mut(),
    };
    // SAFETY: The container is live and uniquely owned, the password is a valid
    // C string or NULL, and the outputs are distinct writable pointer slots.
    let status = unsafe {
        ffi::PKCS12_parse(
            p12.0,
            password.map_or(ptr::null(), CStr::as_ptr),
            &mut parts.key,
            &mut parts.cert,
            &mut parts.ca,
        )
    };
    crate::error::check(status).map_err(Pkcs12Error::PasswordOrData)?;
    let private_key = if parts.key.is_null() {
        None
    } else {
        // SAFETY: The key remains live and exclusively owned by parts.
        Some(unsafe { export_private_key(parts.key) }.map_err(Pkcs12Error::Output)?)
    };
    let certificate = if parts.cert.is_null() {
        None
    } else {
        // SAFETY: The certificate remains exclusively owned by parts.
        Some(unsafe { export_certificate(parts.cert) }.map_err(Pkcs12Error::Output)?)
    };
    // SAFETY: The stack and its elements remain live until parts is dropped.
    let additional_certificates = unsafe { export_stack(parts.ca) }.map_err(Pkcs12Error::Output)?;
    Ok(ParsedPkcs12 {
        private_key,
        certificate,
        additional_certificates,
    })
}

// SAFETY: The key is live and exclusively owned for this call.
#[cfg(any(backend = "openssl", backend = "libressl"))]
pub(crate) unsafe fn export_private_key(key: *mut ffi::EVP_PKEY) -> Result<SecretBytes> {
    // SAFETY: The caller keeps key live; the output is a fresh owned object.
    let p8 = NativePkcs8(pointer(unsafe { ffi::EVP_PKEY2PKCS8(key) })?.as_ptr());
    // SAFETY: The exclusively owned p8 remains unchanged during encoding.
    unsafe { encode_secret(|out| ffi::i2d_PKCS8_PRIV_KEY_INFO(p8.0, out)) }
}

// SAFETY: The key is live and exclusively owned for this call.
#[cfg(any(backend = "boringssl", backend = "awslc"))]
pub(crate) unsafe fn export_private_key(key: *mut ffi::EVP_PKEY) -> Result<SecretBytes> {
    bounded_export(|output| {
        let mut length = 0;
        // SAFETY: Live key and writable output of exactly its advertised capacity.
        // The CBB uses fixed-buffer mode and cannot grow beyond this allocation.
        crate::error::check(unsafe {
            ffi::OB_private_key_pkcs8(key, output.as_mut_ptr(), output.len(), &mut length)
        })?;
        Ok(length)
    })
}

// Fixed caller-owned buffers avoid native reallocations and uncleared private
// octet strings on the forks. Every failed attempt is erased before retrying.
#[cfg(any(test, backend = "boringssl", backend = "awslc"))]
fn bounded_export(mut encoder: impl FnMut(&mut [u8]) -> Result<usize>) -> Result<SecretBytes> {
    let mut capacity = 1024;
    loop {
        let mut output = SecretBytes::from(vec![0; capacity]);
        match encoder(output.as_mut()) {
            Ok(length) => {
                crate::error::check_len_at_most(length, capacity)?;
                return Ok(SecretBytes::from(output.as_ref()[..length].to_vec()));
            }
            Err(error) if capacity == 16 * 1024 * 1024 => return Err(error),
            Err(_) => capacity *= 2,
        }
    }
}

#[cfg(test)]
mod export_tests {
    use super::*;

    #[test]
    fn bounded_exports_retry_only_up_to_the_limit() {
        let mut attempts = Vec::new();
        let output = bounded_export(|out| {
            attempts.push(out.len());
            assert!(out.iter().all(|&b| b == 0));
            out.fill(0x42);
            if out.len() < 1536 {
                Err(Error::InvalidInput("short buffer"))
            } else {
                Ok(1536)
            }
        })
        .unwrap();
        assert_eq!(attempts, [1024, 2048]);
        assert_eq!(output.as_ref(), &[0x42; 1536]);
        assert!(bounded_export(|out| Ok(out.len() + 1)).is_err());
        let mut last = 0;
        assert!(bounded_export(|out| {
            last = out.len();
            Err(Error::InvalidInput("cannot export"))
        })
        .is_err());
        assert_eq!(last, 16 * 1024 * 1024);
    }
}

// SAFETY: The encoder satisfies x509::encode_with's bounded i2d contract.
unsafe fn encode_secret(encoder: impl FnMut(*mut *mut u8) -> i32) -> Result<SecretBytes> {
    // SAFETY: Exactly sized secret storage is erased on every failure path.
    unsafe { crate::x509::encode_with(encoder, |len| SecretBytes::from(vec![0; len])) }
}

// SAFETY: cert is a live, non-null X509 with no concurrent accesses.
unsafe fn export_certificate(cert: *mut ffi::X509) -> Result<Certificate> {
    // SAFETY: The caller keeps cert live and unchanged for both encoding calls.
    let encoded = unsafe { encode_secret(|out| ffi::i2d_X509(cert, out)) }?;
    let mut alias_length = 0;
    // SAFETY: cert is live; alias_length is a writable output slot.
    let alias = unsafe { ffi::X509_alias_get0(cert, &mut alias_length) };
    let alias = if alias.is_null() {
        None
    } else {
        let length = usize::try_from(alias_length)
            .map_err(|_| Error::InvalidState("negative certificate alias length"))?;
        // SAFETY: The alias is borrowed from the live certificate for the
        // backend-reported length. Copy before dropping that certificate.
        Some(unsafe { std::slice::from_raw_parts(alias, length) }.to_vec())
    };
    Ok(Certificate {
        der: encoded.as_ref().to_vec(),
        alias,
    })
}

// SAFETY: stack is NULL or a live X509 stack; elements remain live and are not
// concurrently accessed for this call. All output bytes are copied.
unsafe fn export_stack(stack: *const ffi::stack_st_X509) -> Result<Vec<Certificate>> {
    // SAFETY: The caller supplies a live stack or NULL; the shim handles NULL.
    let count = unsafe { ffi::OB_x509_stack_len(stack) };
    let mut certs = Vec::new();
    for index in 0..count {
        // SAFETY: The stack remains live and the shim also bounds-checks index.
        let cert = pointer(unsafe { ffi::OB_x509_stack_get(stack, index) })?;
        // SAFETY: Each non-null certificate remains owned by the live stack.
        certs.push(unsafe { export_certificate(cert.as_ptr()) }?);
    }
    Ok(certs)
}

#[cfg(any(backend = "openssl", backend = "libressl"))]
pub enum Pkcs7Certificates {
    Signed(Option<Vec<Vec<u8>>>),
    /// The backend's content-type NID, or None when the type is absent.
    Other(Option<i32>),
}

/// Decode certificates from PKCS#7 with the native BER compatibility behavior.
/// This does not verify a signature, certificate chain, or certificate trust.
#[cfg(any(backend = "openssl", backend = "libressl"))]
pub fn parse_pkcs7_certificates(data: &[u8]) -> Result<Pkcs7Certificates> {
    crate::initialize()?;
    struct NativePkcs7(*mut ffi::PKCS7);
    impl Drop for NativePkcs7 {
        fn drop(&mut self) {
            // SAFETY: Sole ownership from d2i_PKCS7.
            unsafe { ffi::PKCS7_free(self.0) };
        }
    }
    let length = data
        .len()
        .try_into()
        .map_err(|_| Error::InvalidInput("PKCS#7 input is too long"))?;
    let mut cursor = data.as_ptr();
    let p7 = NativePkcs7(
        // SAFETY: Decoder has a readable length-bounded input and allocates a fresh
        // object. No native pointer escapes this function.
        pointer(unsafe { ffi::d2i_PKCS7(ptr::null_mut(), &mut cursor, length) })?.as_ptr(),
    );
    // SAFETY: Read type and discriminated union through the selected C headers.
    let kind = unsafe { ffi::OB_pkcs7_kind(p7.0) };
    if kind != ffi::NID_pkcs7_signed as i32 {
        return Ok(Pkcs7Certificates::Other((kind >= 0).then_some(kind)));
    }
    // SAFETY: The shim checks the union discriminator and non-null signed data.
    let certs = unsafe { ffi::OB_pkcs7_certificates(p7.0) };
    let certificates = if certs.is_null() {
        None
    } else {
        Some(
            // SAFETY: The stack is borrowed from the live, exclusively owned p7.
            unsafe { export_stack(certs) }?
                .into_iter()
                .map(|cert| cert.der)
                .collect(),
        )
    };
    Ok(Pkcs7Certificates::Signed(certificates))
}
