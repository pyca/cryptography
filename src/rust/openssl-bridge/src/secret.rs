//! Owned secret buffers without implicit copying or diagnostic formatting.
use crate::ffi;

pub struct SecretBytes(Vec<u8>);
impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}
impl AsRef<[u8]> for SecretBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl AsMut<[u8]> for SecretBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl Drop for SecretBytes {
    fn drop(&mut self) {
        // SAFETY: This uniquely owns the initialized bytes of the allocation.
        unsafe { ffi::OPENSSL_cleanse(self.0.as_mut_ptr().cast(), self.0.len()) };
    }
}

/// Erase an exclusively borrowed byte buffer with the backend's non-elidable wipe.
pub fn erase(bytes: &mut [u8]) {
    // SAFETY: The exclusive slice is writable for its exact initialized length.
    unsafe { ffi::OPENSSL_cleanse(bytes.as_mut_ptr().cast(), bytes.len()) };
}

/// Discard caller-owned output when a native operation or length check fails.
pub(crate) fn clear_on_error<T>(result: crate::Result<T>, output: &mut [u8]) -> crate::Result<T> {
    if result.is_err() {
        erase(output);
    }
    result
}

pub(crate) fn check_shared_secret<const N: usize>(secret: &[u8; N]) -> crate::Result<()> {
    if crate::constant_time_eq(secret, &[0; N]) {
        Err(crate::Error::InvalidInput("shared secret is all zero"))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_order_points_cannot_yield_an_all_zero_shared_secret() {
        assert!(check_shared_secret(&[0; 32]).is_err());
        assert!(check_shared_secret(&[0; 56]).is_err());
        assert!(check_shared_secret(&[1; 32]).is_ok());
        assert!(check_shared_secret(&[1; 56]).is_ok());
    }

    #[test]
    fn errors_erase_only_the_borrowed_output() {
        let mut buffer = [0xa5; 18];
        assert_eq!(clear_on_error(Ok(16), &mut buffer[1..17]).unwrap(), 16);
        assert_eq!(buffer, [0xa5; 18]);
        let error = crate::Error::InvalidState("native failure");
        assert_eq!(
            clear_on_error::<()>(Err(error.clone()), &mut buffer[1..17]),
            Err(error)
        );
        assert_eq!(&buffer[1..17], &[0; 16]);
        assert_eq!((buffer[0], buffer[17]), (0xa5, 0xa5));
    }
}
