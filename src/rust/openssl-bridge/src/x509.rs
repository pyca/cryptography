//! Owned, exclusively accessed native X.509 compatibility objects.
//!
//! Decoding is not trust verification. Names, keys, and verification results
//! are copied rather than exposing native interior pointers. Even getters take
//! exclusive access when native implementations can populate cached encodings.
//! These objects are movable between threads, but are deliberately not Sync.
use crate::{
    encoding::encode,
    error::{check, pointer},
    ffi,
    hash::Algorithm,
    number::Number,
    Error, Result,
};
use std::{
    ffi::{CStr, CString},
    ptr::{self, NonNull},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Encoding {
    Der,
    Pem,
    Text,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameField {
    Subject,
    Issuer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeField {
    NotBefore,
    NotAfter,
}

/// Numeric constants needed at the existing Python compatibility boundary.
/// Values come from the selected headers rather than a guessed ABI table.
pub fn compatibility_constants() -> [(&'static str, u64); 16] {
    [
        ("FILETYPE_PEM", ffi::SSL_FILETYPE_PEM as u64),
        ("FILETYPE_ASN1", ffi::SSL_FILETYPE_ASN1 as u64),
        ("TYPE_RSA", ffi::EVP_PKEY_RSA as u64),
        ("TYPE_DSA", ffi::EVP_PKEY_DSA as u64),
        ("TYPE_DH", ffi::EVP_PKEY_DH as u64),
        ("TYPE_EC", ffi::EVP_PKEY_EC as u64),
        ("CRL_CHECK", ffi::X509_V_FLAG_CRL_CHECK as u64),
        ("CRL_CHECK_ALL", ffi::X509_V_FLAG_CRL_CHECK_ALL as u64),
        ("IGNORE_CRITICAL", ffi::X509_V_FLAG_IGNORE_CRITICAL as u64),
        ("X509_STRICT", ffi::X509_V_FLAG_X509_STRICT as u64),
        (
            "ALLOW_PROXY_CERTS",
            ffi::X509_V_FLAG_ALLOW_PROXY_CERTS as u64,
        ),
        ("POLICY_CHECK", ffi::X509_V_FLAG_POLICY_CHECK as u64),
        ("EXPLICIT_POLICY", ffi::X509_V_FLAG_EXPLICIT_POLICY as u64),
        ("INHIBIT_MAP", ffi::X509_V_FLAG_INHIBIT_MAP as u64),
        (
            "CHECK_SS_SIGNATURE",
            ffi::X509_V_FLAG_CHECK_SS_SIGNATURE as u64,
        ),
        ("PARTIAL_CHAIN", ffi::X509_V_FLAG_PARTIAL_CHAIN as u64),
    ]
}

// Public owners never expose shared mutable native objects. All outward
// references are Rust-owned copies. TLS also uses an internal store guard for
// verification against a permanently frozen factory: only native synchronized
// verification/lookup state may change there, never the trust configuration.
// Store members originate from independent decodes, not mutable caller objects.
macro_rules! owner {
    ($name:ident, $native:ident, $free:ident) => {
        pub struct $name(pub(crate) NonNull<ffi::$native>);
        // SAFETY: The allocation has no thread affinity. Moving this unique
        // owner cannot overlap accesses; it deliberately does not implement Sync.
        unsafe impl Send for $name {}
        impl Drop for $name {
            fn drop(&mut self) {
                // SAFETY: The sole owned reference is released exactly once.
                unsafe { ffi::$free(self.0.as_ptr()) };
            }
        }
    };
}
owner!(Name, X509_NAME, X509_NAME_free);
owner!(Certificate, X509, X509_free);
owner!(TrustStore, X509_STORE, X509_STORE_free);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incomplete_certificates_cannot_be_exported_as_pem() {
        let mut certificate = Certificate::empty().unwrap();
        assert!(certificate.encode(Encoding::Pem).is_err());
        assert!(certificate.signature_algorithm().is_err());
    }

    #[test]
    fn empty_memory_bios_have_no_payload() {
        assert!(Bio::input(&[]).unwrap().bytes().unwrap().is_empty());
        assert!(Bio::memory().unwrap().bytes().unwrap().is_empty());
    }

    #[test]
    fn key_decoders_reject_trailing_bytes_and_missing_strings() {
        let parsed = crate::containers::parse_pkcs12(
            include_bytes!("../tests/vectors/cert-key-aes256cbc.p12"),
            Some(c"cryptography"),
        )
        .unwrap();
        let mut private = parsed.private_key.unwrap().as_ref().to_vec();
        assert!(Key::private_der(&private).is_ok());
        private.push(0);
        assert!(Key::private_der(&private).is_err());
        let mut certificate = Certificate::decode(
            include_bytes!("../tests/vectors/tls-localhost.der"),
            Encoding::Der,
        )
        .unwrap();
        let mut public = certificate.public_key_der().unwrap();
        assert!(Key::public_der(&public).is_ok());
        public.push(0);
        assert!(Key::public_der(&public).is_err());
        // SAFETY: NULL is an explicitly handled absent-string input.
        assert!(unsafe { string_bytes(ptr::null()) }.is_err());
    }

    #[test]
    fn rejecting_password_callback_never_writes_output() {
        let mut out = [0x42u8; 16];
        for writing in [0, 1] {
            assert_eq!(
                no_password(out.as_mut_ptr().cast(), 16, writing, ptr::null_mut()),
                0
            );
            assert_eq!(out, [0x42; 16]);
        }
    }
}

pub(crate) struct Key(pub(crate) NonNull<ffi::EVP_PKEY>);
impl Drop for Key {
    fn drop(&mut self) {
        // SAFETY: Unique ownership of the decoder's returned key reference.
        unsafe { ffi::EVP_PKEY_free(self.0.as_ptr()) };
    }
}
impl Key {
    pub(crate) fn private_der(data: &[u8]) -> Result<Self> {
        let mut cursor = data.as_ptr();
        #[allow(clippy::useless_conversion)]
        let len = crate::error::input_length(data.len(), "key is too long")?;
        // SAFETY: Readable input of checked length; NULL requests a new key.
        let key = Self(pointer(unsafe {
            ffi::d2i_AutoPrivateKey(ptr::null_mut(), &mut cursor, len)
        })?);
        if cursor != data.as_ptr().wrapping_add(data.len()) {
            return Err(Error::InvalidInput("trailing private key data"));
        }
        Ok(key)
    }
    pub(crate) fn public_der(data: &[u8]) -> Result<Self> {
        let mut cursor = data.as_ptr();
        #[allow(clippy::useless_conversion)]
        let len = crate::error::input_length(data.len(), "key is too long")?;
        // SAFETY: Readable input of checked length; NULL requests a new key.
        let key = Self(pointer(unsafe {
            ffi::d2i_PUBKEY(ptr::null_mut(), &mut cursor, len)
        })?);
        if cursor != data.as_ptr().wrapping_add(data.len()) {
            return Err(Error::InvalidInput("trailing public key data"));
        }
        Ok(key)
    }
}

pub(crate) struct Bio(pub(crate) NonNull<ffi::BIO>);
impl Drop for Bio {
    fn drop(&mut self) {
        // SAFETY: This owner always holds one writable memory BIO. Erase its
        // full allocation before freeing, including any private-key input/output.
        unsafe {
            ffi::OB_clear_memory_bio(self.0.as_ptr());
            ffi::BIO_free(self.0.as_ptr());
        }
    }
}
impl Bio {
    pub(crate) fn memory() -> Result<Self> {
        // SAFETY: Static method descriptor, fresh independent memory BIO.
        Ok(Self(pointer(unsafe { ffi::BIO_new(ffi::BIO_s_mem()) })?))
    }
    pub(crate) fn input(data: &[u8]) -> Result<Self> {
        let bio = Self::memory()?;
        let len = crate::error::input_length::<i32>(data.len(), "BIO input is too long")?;
        if len != 0 {
            // SAFETY: The memory BIO copies the readable input; no borrow escapes.
            let written = unsafe { ffi::BIO_write(bio.0.as_ptr(), data.as_ptr().cast(), len) };
            crate::error::check_len(crate::error::check_positive(written)?, len as usize)?;
        }
        Ok(bio)
    }
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>> {
        // SAFETY: Exclusive live memory BIO query.
        let len = unsafe { ffi::OB_bio_pending(self.0.as_ptr()) };
        let length =
            i32::try_from(len).map_err(|_| Error::InvalidState("BIO output is too long"))?;
        let mut out = vec![0; len];
        if length != 0 {
            // SAFETY: The exclusive BIO writes into exactly length output bytes.
            let read = unsafe { ffi::BIO_read(self.0.as_ptr(), out.as_mut_ptr().cast(), length) };
            crate::error::check_len(crate::error::check_positive(read)?, length as usize)?;
        }
        Ok(out)
    }
}

// A NULL PEM password callback permits interactive terminal input. Compatibility
// callers must supply explicit passwords; this callback never touches its inputs.
pub(crate) extern "C" fn no_password(
    _: *mut std::ffi::c_char,
    _: i32,
    _: i32,
    _: *mut std::ffi::c_void,
) -> i32 {
    0
}

// SAFETY: value is NULL or a live native ASN1_STRING for this call, with no mutation.
unsafe fn string_bytes(value: *const ffi::ASN1_STRING) -> Result<Vec<u8>> {
    if value.is_null() {
        return Err(Error::InvalidState("missing ASN.1 string"));
    }
    // SAFETY: The caller provides a live ASN1_STRING.
    let len = usize::try_from(unsafe { ffi::ASN1_STRING_length(value) })
        .map_err(|_| Error::InvalidState("negative ASN.1 string length"))?;
    if len == 0 {
        return Ok(Vec::new());
    }
    // SAFETY: The string remains live throughout this copy of its stored bytes.
    let data = pointer(unsafe { ffi::ASN1_STRING_get0_data(value) }.cast_mut())?;
    // SAFETY: The backend reports a nonzero readable length for this pointer.
    Ok(unsafe { std::slice::from_raw_parts(data.as_ptr(), len) }.to_vec())
}

impl Name {
    pub fn empty() -> Result<Self> {
        crate::initialize()?;
        // SAFETY: Native allocator has no additional preconditions.
        Ok(Self(pointer(unsafe { ffi::X509_NAME_new() })?))
    }
    pub fn from_der(data: &[u8]) -> Result<Self> {
        crate::initialize()?;
        let mut cursor = data.as_ptr();
        #[allow(clippy::useless_conversion)]
        let len = crate::error::input_length(data.len(), "name is too long")?;
        // SAFETY: Input is readable for the checked length; fresh output object.
        let name = Self(pointer(unsafe {
            ffi::d2i_X509_NAME(ptr::null_mut(), &mut cursor, len)
        })?);
        if cursor != data.as_ptr().wrapping_add(data.len()) {
            return Err(Error::InvalidInput("trailing name data"));
        }
        Ok(name)
    }
    pub fn try_clone(&mut self) -> Result<Self> {
        // SAFETY: Exclusive source access covers lazy encoding cache mutation.
        Ok(Self(pointer(unsafe {
            ffi::X509_NAME_dup(self.0.as_ptr())
        })?))
    }
    pub fn der(&mut self) -> Result<Vec<u8>> {
        // SAFETY: The source remains exclusively held and stable across calls.
        unsafe { encode(|out| ffi::i2d_X509_NAME(self.0.as_ptr(), out)) }
    }
    fn attribute_nid(attribute: &CStr) -> Result<i32> {
        // SAFETY: NUL-terminated readable input; no pointer is retained.
        let nid = unsafe { ffi::OBJ_txt2nid(attribute.as_ptr()) };
        if nid == 0 {
            let _ = Error::capture();
            Err(Error::InvalidInput("unknown name attribute"))
        } else {
            Ok(nid)
        }
    }
    /// Replace the first matching attribute. The original remains intact if
    /// allocation or native string validation fails.
    pub fn set(&mut self, attribute: &CStr, utf8: &[u8]) -> Result<()> {
        let nid = Self::attribute_nid(attribute)?;
        let len = crate::error::input_length(utf8.len(), "name value is too long")?;
        let candidate = self.try_clone()?;
        // SAFETY: candidate is a deep independent copy, exclusively held here.
        unsafe {
            let index = ffi::X509_NAME_get_index_by_NID(candidate.0.as_ptr(), nid, -1);
            if index >= 0 {
                let removed = ffi::X509_NAME_delete_entry(candidate.0.as_ptr(), index);
                ffi::X509_NAME_ENTRY_free(removed);
            }
            // MBSTRING_UTF8 is the stable ASN.1 multibyte-string flag (0x1000).
            check(ffi::X509_NAME_add_entry_by_NID(
                candidate.0.as_ptr(),
                nid,
                0x1000,
                utf8.as_ptr(),
                len,
                -1,
                0,
            ))?;
        }
        *self = candidate;
        Ok(())
    }
    pub fn get(&mut self, attribute: &CStr) -> Result<Option<String>> {
        let nid = Self::attribute_nid(attribute)?;
        // SAFETY: All interior pointers remain inside this exclusive call. The
        // conversion allocates an independent buffer, copied then freed once.
        unsafe {
            let index = ffi::X509_NAME_get_index_by_NID(self.0.as_ptr(), nid, -1);
            if index < 0 {
                return Ok(None);
            }
            let entry = pointer(ffi::X509_NAME_get_entry(self.0.as_ptr(), index) as *mut _)?;
            let data = ffi::X509_NAME_ENTRY_get_data(entry.as_ptr());
            let mut out = ptr::null_mut();
            let len = ffi::ASN1_STRING_to_UTF8(&mut out, data);
            if len < 0 {
                // NO-COVERAGE-START
                // Decoded and added names have already passed native string validation;
                // this conversion failure requires native allocation failure.
                ffi::OB_free(out.cast());
                return Err(Error::capture());
                // NO-COVERAGE-END
            }
            let bytes = if len == 0 {
                Vec::new()
            } else {
                let p = pointer(out)?;
                std::slice::from_raw_parts(p.as_ptr(), len as usize).to_vec()
            };
            ffi::OB_free(out.cast());
            String::from_utf8(bytes)
                .map(Some)
                .map_err(|_| Error::InvalidState("native name conversion is not UTF-8"))
        }
    }
    pub fn components(&mut self) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let mut out = Vec::new();
        // SAFETY: Entries and values are borrowed only during exclusive access;
        // all returned values and backend-owned attribute names are copied.
        unsafe {
            for index in 0..ffi::X509_NAME_entry_count(self.0.as_ptr()) {
                let entry = pointer(ffi::X509_NAME_get_entry(self.0.as_ptr(), index) as *mut _)?;
                let object = ffi::X509_NAME_ENTRY_get_object(entry.as_ptr());
                let nid = ffi::OBJ_obj2nid(object);
                let short = ffi::OBJ_nid2sn(nid);
                // NID_undef has the non-null short name "UNDEF". Preserve an
                // unregistered attribute's numeric OID instead of that label.
                let name = if nid == 0 || short.is_null() {
                    let len = ffi::OBJ_obj2txt(ptr::null_mut(), 0, object, 1);
                    if len < 0 || len == i32::MAX {
                        // NO-COVERAGE-START
                        // The immutable decoded OID has bounded, stable text length;
                        // these guards protect against a violated native encoder
                        // contract.
                        return Err(Error::capture());
                        // NO-COVERAGE-END
                    }
                    let mut buf = vec![0u8; len as usize + 1];
                    if ffi::OBJ_obj2txt(buf.as_mut_ptr().cast(), len + 1, object, 1) != len {
                        // NO-COVERAGE-START
                        // The immutable decoded OID has bounded, stable text length;
                        // these guards protect against a violated native encoder
                        // contract.
                        return Err(Error::capture());
                        // NO-COVERAGE-END
                    }
                    buf.pop();
                    buf
                } else {
                    CStr::from_ptr(short).to_bytes().to_vec()
                };
                out.push((
                    name,
                    string_bytes(ffi::X509_NAME_ENTRY_get_data(entry.as_ptr()))?,
                ));
            }
        }
        Ok(out)
    }
    pub fn compare(&mut self, other: &mut Self) -> std::cmp::Ordering {
        // SAFETY: Distinct exclusive owners; comparison may update native caches.
        unsafe { ffi::X509_NAME_cmp(self.0.as_ptr(), other.0.as_ptr()) }.cmp(&0)
    }
    pub fn hash(&mut self) -> u64 {
        // SAFETY: Exclusive source access covers native cache updates.
        unsafe { ffi::OB_x509_name_hash(self.0.as_ptr()) as u64 }
    }
    pub fn display(&mut self) -> Result<String> {
        // SAFETY: NULL requests a native allocation, copied and freed below.
        let out = pointer(unsafe { ffi::X509_NAME_oneline(self.0.as_ptr(), ptr::null_mut(), 0) })?;
        // SAFETY: X509_NAME_oneline returns a NUL-terminated allocated string.
        let text = unsafe { CStr::from_ptr(out.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: This call owns exactly the allocation returned above.
        unsafe { ffi::OB_free(out.as_ptr().cast()) };
        Ok(text)
    }
}

impl Certificate {
    /// Construct an incomplete legacy certificate. It cannot be installed in a
    /// TLS context or trust store until it can be encoded and independently decoded.
    pub fn empty() -> Result<Self> {
        crate::initialize()?;
        // SAFETY: Native allocator has no additional preconditions.
        Ok(Self(pointer(unsafe { ffi::X509_new() })?))
    }
    pub fn decode(data: &[u8], encoding: Encoding) -> Result<Self> {
        crate::initialize()?;
        let bio = Bio::input(data)?;
        // SAFETY: Fresh output; BIO owns all input. Certificates have no password
        // callback. No pointer to input or BIO is retained in the decoded object.
        let cert = unsafe {
            match encoding {
                Encoding::Der => ffi::d2i_X509_bio(bio.0.as_ptr(), ptr::null_mut()),
                Encoding::Pem => {
                    ffi::PEM_read_bio_X509(bio.0.as_ptr(), ptr::null_mut(), None, ptr::null_mut())
                }
                Encoding::Text => {
                    return Err(Error::InvalidInput(
                        "text is not a certificate input format",
                    ))
                }
            }
        };
        Ok(Self(pointer(cert)?))
    }
    pub fn encode(&mut self, encoding: Encoding) -> Result<Vec<u8>> {
        if encoding != Encoding::Text {
            // SAFETY: These getters borrow immutable fields of this exclusive
            // certificate. Inspect the raw bit strings without decoding an EVP
            // key, so unknown public-key algorithms can still be preserved.
            unsafe {
                let mut signature = ptr::null();
                let mut algorithm = ptr::null();
                ffi::X509_get0_signature(&mut signature, &mut algorithm, self.0.as_ptr());
                let public_key = ffi::X509_get0_pubkey_bitstr(self.0.as_ptr());
                if signature.is_null()
                    || public_key.is_null()
                    || ffi::ASN1_STRING_length(signature) <= 0
                    || ffi::ASN1_STRING_length(public_key) <= 0
                {
                    return Err(Error::InvalidState(
                        "certificate encoding requires a signature and public key",
                    ));
                }
            }
        }
        let mut bio = Bio::memory()?;
        // SAFETY: Exclusive certificate access and fresh output BIO. No native
        // object or buffer can be concurrently modified during serialization.
        check(unsafe {
            match encoding {
                Encoding::Der => ffi::i2d_X509_bio(bio.0.as_ptr(), self.0.as_ptr()),
                Encoding::Pem => ffi::PEM_write_bio_X509(bio.0.as_ptr(), self.0.as_ptr()),
                Encoding::Text => ffi::X509_print_ex(bio.0.as_ptr(), self.0.as_ptr(), 0, 0),
            }
            // NO-COVERAGE-START
            // Required fields were checked above; the owned memory BIO can fail
            // here only in native encoding/allocation, not caller callbacks.
        })?;
        // NO-COVERAGE-END
        bio.bytes()
    }
    pub fn try_clone(&mut self) -> Result<Self> {
        // SAFETY: Exclusive access covers the native serialization cache. The
        // returned object is a deep copy, with no mutable interior aliasing.
        Ok(Self(pointer(unsafe { ffi::X509_dup(self.0.as_ptr()) })?))
    }
    pub fn version(&mut self) -> i64 {
        // SAFETY: Live, exclusively accessed certificate.
        unsafe { ffi::X509_get_version(self.0.as_ptr()) as i64 }
    }
    pub fn set_version(&mut self, version: i64) -> Result<()> {
        #[allow(clippy::useless_conversion)]
        let version = version
            .try_into()
            .map_err(|_| Error::InvalidInput("version is out of range"))?;
        // SAFETY: The native setter copies the value into this exclusive owner.
        check(unsafe { ffi::X509_set_version(self.0.as_ptr(), version) })
    }
    pub fn name(&mut self, field: NameField) -> Result<Name> {
        // SAFETY: The borrowed name remains inside this exclusive call and is
        // deep-copied before return. No interior pointer escapes.
        unsafe {
            let name = match field {
                NameField::Subject => ffi::X509_get_subject_name(self.0.as_ptr()),
                NameField::Issuer => ffi::X509_get_issuer_name(self.0.as_ptr()),
            };
            let name = pointer(name as *mut _)?;
            Ok(Name(pointer(ffi::X509_NAME_dup(name.as_ptr()))?))
        }
    }
    pub fn set_name(&mut self, field: NameField, name: &mut Name) -> Result<()> {
        // SAFETY: Both objects are exclusive; native setters copy the name.
        check(unsafe {
            match field {
                NameField::Subject => ffi::X509_set_subject_name(self.0.as_ptr(), name.0.as_ptr()),
                NameField::Issuer => ffi::X509_set_issuer_name(self.0.as_ptr(), name.0.as_ptr()),
            }
        })
    }
    pub fn public_key_der(&mut self) -> Result<Vec<u8>> {
        // SAFETY: Getter returns an owned key reference held only in this call.
        let key = Key(pointer(unsafe { ffi::X509_get_pubkey(self.0.as_ptr()) })?);
        // SAFETY: Key and its containing certificate cannot mutate during encoding.
        unsafe { encode(|out| ffi::i2d_PUBKEY(key.0.as_ptr(), out)) }
    }
    pub fn set_public_key_der(&mut self, der: &[u8]) -> Result<()> {
        let key = Key::public_der(der)?;
        // SAFETY: The certificate retains its own reference to an independent key.
        check(unsafe { ffi::X509_set_pubkey(self.0.as_ptr(), key.0.as_ptr()) })
    }
    /// Sign using a private-key DER encoding. This does not validate certificate
    /// policy, names, or trust. The native key never escapes the signing operation.
    pub fn sign(&mut self, private_der: &[u8], digest: Algorithm) -> Result<()> {
        let key = Key::private_der(private_der)?;
        // SAFETY: Exclusive certificate and freshly decoded private key, with
        // a live immutable digest descriptor and no callbacks or retained borrows.
        let written = unsafe { ffi::X509_sign(self.0.as_ptr(), key.0.as_ptr(), digest.as_ptr()) };
        crate::error::check_positive(written)?;
        Ok(())
    }
    pub fn signature_algorithm(&mut self) -> Result<Vec<u8>> {
        // SAFETY: The signature algorithm is borrowed only in this exclusive call;
        // its backend-owned name is copied before returning.
        unsafe {
            let alg = ffi::X509_get0_tbs_sigalg(self.0.as_ptr());
            if alg.is_null() {
                // NO-COVERAGE-START
                // X509_new and successful decoders initialize these algorithm fields,
                // even for an undefined OID; retain native NULL guards.
                return Err(Error::InvalidState("undefined signature algorithm"));
                // NO-COVERAGE-END
            }
            let mut object = ptr::null();
            ffi::X509_ALGOR_get0(&mut object, ptr::null_mut(), ptr::null_mut(), alg);
            if object.is_null() {
                // NO-COVERAGE-START
                // X509_new and successful decoders initialize these algorithm fields,
                // even for an undefined OID; retain native NULL guards.
                return Err(Error::InvalidState("undefined signature algorithm"));
                // NO-COVERAGE-END
            }
            let nid = ffi::OBJ_obj2nid(object);
            if nid == 0 {
                return Err(Error::InvalidState("undefined signature algorithm"));
            }
            let name = pointer(ffi::OBJ_nid2ln(nid).cast_mut())?;
            Ok(CStr::from_ptr(name.as_ptr()).to_bytes().to_vec())
        }
    }
    pub fn digest(&mut self, digest: Algorithm) -> Result<Vec<u8>> {
        let mut out = vec![0; digest.output_size()?];
        let mut len = 0;
        // SAFETY: Exclusive certificate, fixed-output digest and sufficient
        // writable output. The backend writes the digest's fixed output size.
        check(unsafe {
            ffi::X509_digest(self.0.as_ptr(), digest.as_ptr(), out.as_mut_ptr(), &mut len)
        })?;
        crate::error::check_len(len as usize, out.len())?;
        Ok(out)
    }
    pub fn serial(&mut self) -> Result<(bool, Vec<u8>)> {
        // SAFETY: Exclusive certificate; conversion returns a fresh BIGNUM.
        unsafe {
            let serial = pointer(ffi::X509_get_serialNumber(self.0.as_ptr()))?;
            let number = pointer(ffi::ASN1_INTEGER_to_BN(serial.as_ptr(), ptr::null_mut()))?;
            let negative = ffi::BN_is_negative(number.as_ptr()) != 0;
            let copy = Number::copy_raw(number.as_ptr());
            ffi::BN_free(number.as_ptr());
            Ok((negative, copy?.secret_bytes()?.as_ref().to_vec()))
        }
    }
    pub fn set_serial(&mut self, unsigned: &[u8]) -> Result<()> {
        let number = Number::from_bytes(unsigned, i32::MAX as usize)?;
        // SAFETY: Live unsigned integer converted to a fresh ASN.1 integer. The
        // setter copies it, so the temporary is freed on both success and error.
        unsafe {
            let serial = pointer(ffi::BN_to_ASN1_INTEGER(number.ptr(), ptr::null_mut()))?;
            let result = ffi::X509_set_serialNumber(self.0.as_ptr(), serial.as_ptr());
            ffi::ASN1_INTEGER_free(serial.as_ptr());
            check(result)
        }
    }
    fn time_ptr(&mut self, field: TimeField) -> Result<NonNull<ffi::ASN1_TIME>> {
        // SAFETY: Interior pointer remains confined to exclusive methods below.
        pointer(unsafe {
            match field {
                TimeField::NotBefore => ffi::OB_x509_not_before(self.0.as_ptr()),
                TimeField::NotAfter => ffi::OB_x509_not_after(self.0.as_ptr()),
            }
        })
    }
    pub fn time(&mut self, field: TimeField) -> Result<Option<Vec<u8>>> {
        let time = self.time_ptr(field)?;
        // SAFETY: Borrowed time remains inside this exclusive call. A temporary
        // generalized-time allocation is copied and then freed exactly once.
        unsafe {
            if ffi::ASN1_STRING_length(time.as_ptr()) == 0 {
                return Ok(None);
            }
            if ffi::ASN1_STRING_type(time.as_ptr()) == ffi::V_ASN1_GENERALIZEDTIME as i32 {
                return string_bytes(time.as_ptr()).map(Some);
            }
            let generalized = pointer(ffi::ASN1_TIME_to_generalizedtime(
                time.as_ptr(),
                ptr::null_mut(),
            ))?;
            let bytes = string_bytes(generalized.as_ptr());
            ffi::ASN1_GENERALIZEDTIME_free(generalized.as_ptr());
            bytes.map(Some)
        }
    }
    pub fn set_time(&mut self, field: TimeField, value: &CStr) -> Result<()> {
        let time = self.time_ptr(field)?;
        // SAFETY: Validate before mutation; value is NUL-terminated. The native
        // setter copies it and retains no reference to Rust memory.
        unsafe {
            if ffi::ASN1_TIME_set_string(ptr::null_mut(), value.as_ptr()) != 1 {
                let _ = Error::capture();
                return Err(Error::InvalidInput("invalid ASN.1 time"));
            }
            check(ffi::ASN1_TIME_set_string(time.as_ptr(), value.as_ptr()))
        }
    }
    pub fn adjust_time(&mut self, field: TimeField, seconds: i64) -> Result<()> {
        let time = self.time_ptr(field)?;
        #[allow(clippy::useless_conversion)]
        let offset = seconds
            .try_into()
            .map_err(|_| Error::InvalidInput("time offset is out of range"))?;
        // SAFETY: Exclusive borrowed time, checked native integer offset.
        pointer(unsafe { ffi::X509_gmtime_adj(time.as_ptr(), offset) }).map(|_| ())
    }
    pub fn extension_count(&mut self) -> usize {
        // SAFETY: Exclusive initialized certificate query.
        unsafe { ffi::X509_get_ext_count(self.0.as_ptr()).max(0) as usize }
    }
}

pub(crate) struct CertificateStack(pub(crate) NonNull<ffi::stack_st_X509>);
impl Drop for CertificateStack {
    fn drop(&mut self) {
        // SAFETY: This stack owns each contained certificate reference.
        unsafe { ffi::OB_x509_stack_free(self.0.as_ptr()) };
    }
}
impl CertificateStack {
    pub(crate) fn from_der(chain: &[Vec<u8>]) -> Result<Self> {
        // SAFETY: Allocates an empty independent stack.
        let stack = Self(pointer(unsafe { ffi::OB_x509_stack_new() })?);
        for der in chain {
            let cert = Certificate::decode(der, Encoding::Der)?;
            // SAFETY: On success the stack owns the reference; failure leaves
            // ownership with cert. Previously inserted members are RAII-owned.
            check(unsafe { ffi::OB_x509_stack_push(stack.0.as_ptr(), cert.0.as_ptr()) })?;
            std::mem::forget(cert);
        }
        Ok(stack)
    }
    pub(crate) fn der(&mut self) -> Result<Vec<Vec<u8>>> {
        let mut out = Vec::new();
        // SAFETY: The stack retains each immutable certificate while duplicating
        // it. Store-derived references can also be used by other verification
        // contexts: encode only an independently owned duplicate.
        unsafe {
            for index in 0..ffi::OB_x509_stack_len(self.0.as_ptr()) {
                let cert = pointer(ffi::OB_x509_stack_get(self.0.as_ptr(), index))?;
                let mut owned = Certificate(pointer(ffi::X509_dup(cert.as_ptr()))?);
                out.push(owned.encode(Encoding::Der)?);
            }
        }
        Ok(out)
    }
}

#[derive(Debug)]
pub struct VerificationFailure {
    pub code: i32,
    pub depth: i32,
    pub message: String,
    pub certificate_der: Option<Vec<u8>>,
}

#[derive(Debug)]
pub enum VerificationError {
    Backend(Error),
    Untrusted(VerificationFailure),
}
impl From<Error> for VerificationError {
    fn from(error: Error) -> Self {
        Self::Backend(error)
    }
}

impl TrustStore {
    pub fn new() -> Result<Self> {
        crate::initialize()?;
        // SAFETY: Fresh native owner with no additional allocator preconditions.
        Ok(Self(pointer(unsafe { ffi::X509_STORE_new() })?))
    }
    pub fn add_certificate_der(&mut self, der: &[u8]) -> Result<()> {
        let cert = Certificate::decode(der, Encoding::Der)?;
        // SAFETY: Store retains a reference to the freshly decoded independent
        // certificate. It can never alias a caller's mutable certificate object.
        check(unsafe { ffi::X509_STORE_add_cert(self.0.as_ptr(), cert.0.as_ptr()) })
    }
    pub fn add_crl_der(&mut self, der: &[u8]) -> Result<()> {
        let bio = Bio::input(der)?;
        // SAFETY: The input BIO owns the bytes; decoder returns an owned CRL.
        let crl = pointer(unsafe { ffi::d2i_X509_CRL_bio(bio.0.as_ptr(), ptr::null_mut()) })?;
        // SAFETY: The store takes its own reference on success; this call always
        // releases the decoder reference. No mutable CRL alias escapes.
        unsafe {
            let result = ffi::X509_STORE_add_crl(self.0.as_ptr(), crl.as_ptr());
            ffi::X509_CRL_free(crl.as_ptr());
            check(result)
        }
    }
    pub fn set_flags(&mut self, flags: u64) -> Result<()> {
        #[allow(clippy::useless_conversion)]
        let flags = flags
            .try_into()
            .map_err(|_| Error::InvalidInput("verification flags are out of range"))?;
        // SAFETY: Exclusive native store; flags contain no pointers or callbacks.
        check(unsafe { ffi::X509_STORE_set_flags(self.0.as_ptr(), flags) })
    }
    pub fn set_time(&mut self, unix_seconds: i64) -> Result<()> {
        // SAFETY: Exclusive live store. The C shim checks the native time_t
        // width using the target C compiler and updates the store's owned
        // parameters. Only fixed-width integers cross the Rust ABI.
        match unsafe { ffi::OB_store_set_time(self.0.as_ptr(), unix_seconds) } {
            // NO-COVERAGE-START
            // All CI targets use 64-bit native time_t; the C shim also protects
            // platforms with narrower time_t.
            -1 => Err(Error::InvalidInput("verification time is out of range")),
            // NO-COVERAGE-END
            result => check(result),
        }
    }
    pub fn load_locations(&mut self, file: Option<&CStr>, directory: Option<&CStr>) -> Result<()> {
        // SAFETY: Strings are terminated, live for the synchronous call, and
        // copied by the native lookup implementation if retained.
        check(unsafe {
            ffi::X509_STORE_load_locations(
                self.0.as_ptr(),
                file.map_or(ptr::null(), CStr::as_ptr),
                directory.map_or(ptr::null(), CStr::as_ptr),
            )
        })
    }
    pub fn verify(
        &mut self,
        leaf_der: &[u8],
        untrusted_der: &[Vec<u8>],
    ) -> std::result::Result<Vec<Vec<u8>>, VerificationError> {
        struct Context(NonNull<ffi::X509_STORE_CTX>);
        impl Drop for Context {
            fn drop(&mut self) {
                // SAFETY: Sole ownership; store and inputs outlive this context.
                unsafe { ffi::X509_STORE_CTX_free(self.0.as_ptr()) };
            }
        }
        let leaf = Certificate::decode(leaf_der, Encoding::Der)?;
        let chain = CertificateStack::from_der(untrusted_der)?;
        // SAFETY: Fresh native verification context.
        let ctx = Context(pointer(unsafe { ffi::X509_STORE_CTX_new() })?);
        // SAFETY: Leaf/chain are exclusive and all inputs outlive ctx. The
        // store is exclusively owned, or a TLS factory's frozen configuration
        // using native synchronized lookups. No store mutation or application
        // callback is exposed and no borrowed pointer escapes this method.
        unsafe {
            check(ffi::X509_STORE_CTX_init(
                ctx.0.as_ptr(),
                self.0.as_ptr(),
                leaf.0.as_ptr(),
                chain.0.as_ptr(),
            ))?;
            let status = ffi::X509_verify_cert(ctx.0.as_ptr());
            if status != 1 {
                let code = ffi::X509_STORE_CTX_get_error(ctx.0.as_ptr());
                let depth = ffi::X509_STORE_CTX_get_error_depth(ctx.0.as_ptr());
                let message = ffi::X509_verify_cert_error_string(code.into());
                let message = if message.is_null() {
                    // NO-COVERAGE-START
                    // Supported backends return static text even for unknown
                    // verification codes; retain a NULL diagnostic fallback.
                    "unknown certificate verification failure".into()
                    // NO-COVERAGE-END
                } else {
                    CStr::from_ptr(message).to_string_lossy().into_owned()
                };
                let cert = ffi::X509_STORE_CTX_get_current_cert(ctx.0.as_ptr());
                let certificate_der = if cert.is_null() {
                    // NO-COVERAGE-START
                    // Normal verification failures identify the supplied leaf or an
                    // issuer; NULL is a native internal-failure diagnostic fallback.
                    None
                    // NO-COVERAGE-END
                } else {
                    let mut owned = Certificate(pointer(ffi::X509_dup(cert))?);
                    Some(owned.encode(Encoding::Der)?)
                };
                let _ = Error::capture();
                return Err(VerificationError::Untrusted(VerificationFailure {
                    code,
                    depth,
                    message,
                    certificate_der,
                }));
            }
            // get1_chain owns references, not deep clones. der() duplicates
            // each immutable certificate before exporting its encoding.
            let mut verified =
                CertificateStack(pointer(ffi::X509_STORE_CTX_get1_chain(ctx.0.as_ptr()))?);
            verified.der().map_err(VerificationError::Backend)
        }
    }
}

pub fn c_string(bytes: &[u8]) -> Result<CString> {
    CString::new(bytes).map_err(|_| Error::InvalidInput("value contains NUL"))
}
