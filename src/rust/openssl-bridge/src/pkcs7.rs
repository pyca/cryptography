//! One-shot native PKCS#7 signature verification for OpenSSL and LibreSSL.
use crate::{
    error::{check, pointer},
    ffi, Result,
};
use std::ptr;

#[derive(Clone, Copy)]
pub enum Encoding {
    Der,
    Pem,
    Smime,
}

struct Bio(*mut ffi::BIO);
impl Drop for Bio {
    fn drop(&mut self) {
        // SAFETY: Sole ownership of this BIO; no BIO chains are constructed.
        unsafe { ffi::BIO_free(self.0) };
    }
}
struct Pkcs7(*mut ffi::PKCS7);
impl Drop for Pkcs7 {
    fn drop(&mut self) {
        // SAFETY: Sole ownership of the decoded PKCS7.
        unsafe { ffi::PKCS7_free(self.0) };
    }
}
struct Store(*mut ffi::X509_STORE);
impl Drop for Store {
    fn drop(&mut self) {
        // SAFETY: Sole ownership of the store; it owns its certificate references.
        unsafe { ffi::X509_STORE_free(self.0) };
    }
}
struct Certificate(*mut ffi::X509);
impl Drop for Certificate {
    fn drop(&mut self) {
        // SAFETY: Releases exactly the reference obtained from d2i_X509.
        unsafe { ffi::X509_free(self.0) };
    }
}

/// Verify signatures and certificate chains using only the supplied DER trust
/// anchors and certificates embedded in the message. Native default paths are
/// not loaded. `text` requests PKCS#7 MIME text handling. For detached signatures,
/// pass the content explicitly; no unauthenticated output is returned.
pub fn verify(
    encoding: Encoding,
    signature: &[u8],
    content: Option<&[u8]>,
    trust_anchors: &[&[u8]],
    text: bool,
) -> Result<()> {
    crate::initialize()?;
    let length = crate::error::input_length(signature.len(), "PKCS#7 signature is too long")?;
    let input = Bio(
        // SAFETY: Explicit nonnegative length, readable signature; this BIO is
        // dropped before signature's borrow ends. It does not own the slice.
        pointer(unsafe { ffi::BIO_new_mem_buf(signature.as_ptr().cast(), length) })?.as_ptr(),
    );
    // The detached S/MIME body is also an owned output, including on failure.
    let mut smime_body = Bio(ptr::null_mut());
    let message = Pkcs7(
        // SAFETY: Live input BIO; fresh output objects; no password callback is used.
        pointer(unsafe {
            match encoding {
                Encoding::Der => ffi::d2i_PKCS7_bio(input.0, ptr::null_mut()),
                Encoding::Pem => {
                    ffi::PEM_read_bio_PKCS7(input.0, ptr::null_mut(), None, ptr::null_mut())
                }
                Encoding::Smime => ffi::SMIME_read_PKCS7(input.0, &mut smime_body.0),
            }
        })?
        .as_ptr(),
    );
    // SAFETY: No arguments; returns a newly allocated store.
    let store = Store(pointer(unsafe { ffi::X509_STORE_new() })?.as_ptr());
    for der in trust_anchors {
        let mut cursor = der.as_ptr();
        let length = crate::error::input_length(der.len(), "certificate is too long")?;
        let cert = Certificate(
            // SAFETY: The decoder reads the bounded DER input and creates a new object.
            pointer(unsafe { ffi::d2i_X509(ptr::null_mut(), &mut cursor, length) })?.as_ptr(),
        );
        // SAFETY: Both objects are live and exclusively owned. The store retains
        // its own certificate reference on success; ours is dropped each loop.
        check(unsafe { ffi::X509_STORE_add_cert(store.0, cert.0) })?;
    }
    let data = if let Some(content) = content {
        let length = crate::error::input_length(content.len(), "PKCS#7 content is too long")?;
        // SAFETY: The content slice remains live through verification and the
        // BIO's drop. Explicit length avoids the native strlen convention.
        Bio(pointer(unsafe { ffi::BIO_new_mem_buf(content.as_ptr().cast(), length) })?.as_ptr())
    } else {
        Bio(ptr::null_mut())
    };
    let flags = if text { ffi::PKCS7_TEXT as i32 } else { 0 };
    // SAFETY: All objects remain live and exclusively owned; NULL external
    // certificate stack selects embedded certs. No unbounded output buffer is
    // supplied, and flags cannot disable signature or certificate validation.
    check(unsafe {
        ffi::PKCS7_verify(
            message.0,
            ptr::null_mut(),
            store.0,
            data.0,
            ptr::null_mut(),
            flags,
        )
    })
}
