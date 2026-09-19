//! Narrow compatibility for deprecated pyOpenSSL private-key export and DSA
//! generation. New applications should use typed key-generation interfaces and
//! explicit modern serialization policies instead of these legacy choices.
use crate::{
    containers::export_private_key,
    error::{check, pointer},
    ffi,
    secret::SecretBytes,
    x509::{Bio, Key},
    Error, Result,
};
use std::{ffi::CStr, ptr};

/// Names of the backend's built-in EC groups. A cryptographic group being
/// available does not guarantee it is permitted for TLS key exchange.
pub fn curve_names() -> Result<Vec<String>> {
    crate::initialize()?;
    // SAFETY: NULL with zero capacity queries the immutable built-in table.
    let count = unsafe { ffi::EC_get_builtin_curves(ptr::null_mut(), 0) };
    if count > 1024 {
        return Err(Error::InvalidState("unexpected number of built-in curves"));
    }
    let mut curves = vec![
        ffi::EC_builtin_curve {
            nid: 0,
            comment: ptr::null()
        };
        count
    ];
    // SAFETY: The vector covers exactly the advertised capacity. The native
    // immutable table fills each entry and retains no reference to the vector.
    if unsafe { ffi::EC_get_builtin_curves(curves.as_mut_ptr(), curves.len()) } != count {
        return Err(Error::InvalidState("built-in curve table changed"));
    }
    let mut names = Vec::new();
    for curve in curves {
        // SAFETY: A built-in curve NID has a backend-owned static short name.
        let name = pointer(unsafe { ffi::OBJ_nid2sn(curve.nid) }.cast_mut())?;
        names.push(
            // SAFETY: The name is a live NUL-terminated static string, copied here.
            unsafe { CStr::from_ptr(name.as_ptr()) }
                .to_string_lossy()
                .into_owned(),
        );
    }
    Ok(names)
}

/// Preserve the old DSA generator's explicitly requested sizes, including weak
/// historical sizes. This interface does not imply suitability for new keys.
/// Inputs outside the bounded legacy range are rejected before native calls.
pub fn dsa_private_key_der(bits: u32) -> Result<SecretBytes> {
    if !(512..=4096).contains(&bits) || bits % 64 != 0 {
        return Err(Error::InvalidInput(
            "legacy DSA size must be a multiple of 64 in 512..=4096",
        ));
    }
    crate::initialize()?;
    struct Dsa(*mut ffi::DSA);
    impl Drop for Dsa {
        fn drop(&mut self) {
            // SAFETY: Sole reference to a native DSA allocation.
            unsafe { ffi::DSA_free(self.0) };
        }
    }
    // SAFETY: Fresh independent native allocations.
    let dsa = Dsa(pointer(unsafe { ffi::DSA_new() })?.as_ptr());
    // SAFETY: Fresh independent native key allocation.
    let key = Key(pointer(unsafe { ffi::EVP_PKEY_new() })?);
    // SAFETY: Unique DSA, bounded bit size, native RNG, no user callbacks.
    check(unsafe {
        ffi::DSA_generate_parameters_ex(
            dsa.0,
            bits as _,
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    })?;
    // SAFETY: Parameter generation succeeded and DSA remains exclusive.
    check(unsafe { ffi::DSA_generate_key(dsa.0) })?;
    // SAFETY: Both owners stay local; set1 takes its own reference on success.
    check(unsafe { ffi::EVP_PKEY_set1_DSA(key.0.as_ptr(), dsa.0) })?;
    // SAFETY: The fully generated private key is exclusively accessed here.
    unsafe { export_private_key(key.0.as_ptr()) }
}

// A NULL password callback would permit OpenSSL to prompt on the terminal.
// Always reject such implicit input; callers must provide a bounded byte string.
unsafe extern "C" fn no_password(
    _: *mut std::ffi::c_char,
    _: i32,
    _: i32,
    _: *mut std::ffi::c_void,
) -> i32 {
    0
}

/// Export the legacy PEM form using the native named cipher. Encryption is
/// requested only when both cipher and password are present; embedded NUL bytes
/// in passwords remain data. Private temporary BIO storage is erased on drop.
pub fn private_key_pem(
    der: &[u8],
    cipher: Option<&CStr>,
    password: Option<&[u8]>,
) -> Result<SecretBytes> {
    if cipher.is_some() != password.is_some() {
        return Err(Error::InvalidInput(
            "cipher and password must be supplied together",
        ));
    }
    let key = Key::private_der(der)?;
    let mut bio = Bio::memory()?;
    let cipher = match cipher {
        None => ptr::null(),
        Some(name) => {
            // SAFETY: Readable terminated name; result is an immutable descriptor.
            let cipher = unsafe { ffi::EVP_get_cipherbyname(name.as_ptr()) };
            if cipher.is_null() {
                return Err(Error::InvalidInput("invalid cipher name"));
            }
            cipher
        }
    };
    // LibreSSL's historical signature accepts a mutable password pointer.
    // Give it owned, erased storage instead of casting away a Rust borrow.
    let mut password = SecretBytes::from(password.unwrap_or(b"").to_vec());
    let len = i32::try_from(password.as_ref().len())
        .map_err(|_| Error::InvalidInput("password is too long"))?;
    // SAFETY: The private key and output BIO are exclusive. A provided password
    // is readable for its explicit length, including NULs. When encrypted, the
    // non-NULL explicit password prevents prompting. Do not also install a
    // callback: OpenSSL's encoder replaces an explicit password with it. The
    // unencrypted case has a rejecting callback and cannot prompt either.
    check(unsafe {
        ffi::PEM_write_bio_PrivateKey(
            bio.0.as_ptr(),
            key.0.as_ptr(),
            cipher,
            password.as_mut().as_mut_ptr(),
            len,
            if cipher.is_null() {
                Some(no_password)
            } else {
                None
            },
            ptr::null_mut(),
        )
    })?;
    Ok(bio.bytes()?.into())
}

/// The deprecated human-readable RSA dump includes secret values. Its returned
/// buffer and native staging allocation are erased when their owners are dropped.
pub fn rsa_private_key_text(der: &[u8]) -> Result<SecretBytes> {
    let key = Key::private_der(der)?;
    let mut bio = Bio::memory()?;
    // SAFETY: The getter returns an owned RSA reference or NULL for a wrong type.
    let rsa = pointer(unsafe { ffi::EVP_PKEY_get1_RSA(key.0.as_ptr()) })?;
    // SAFETY: The RSA is live, exclusively used, and the output BIO is owned.
    let status = unsafe { ffi::RSA_print(bio.0.as_ptr(), rsa.as_ptr(), 0) };
    // SAFETY: Release exactly the get1 reference on both success and error.
    unsafe { ffi::RSA_free(rsa.as_ptr()) };
    check(status)?;
    Ok(bio.bytes()?.into())
}
