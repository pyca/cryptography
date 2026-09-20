//! Internal DER encoding with a shared native length and cursor contract.
//! Private encodings use storage that is erased on success and error paths.
#[cfg(any(backend = "openssl", backend = "libressl"))]
use crate::secret::SecretBytes;
use crate::{Error, Result};
use std::ptr;

// SAFETY contract: encoder is an i2d-style function on an exclusively held,
// initialized native object. It may fail, but must never write beyond the queried
// capacity. On success it advances the cursor by exactly the returned length.
pub(crate) unsafe fn encode(encoder: impl FnMut(*mut *mut u8) -> i32) -> Result<Vec<u8>> {
    // SAFETY: The caller supplies the encoder contract; the allocation is exact.
    unsafe { encode_with(encoder, |len| vec![0; len]) }
}

// SAFETY: Same encoder contract as encode. allocate must return exactly len bytes.
unsafe fn encode_with<T: AsMut<[u8]>>(
    mut encoder: impl FnMut(*mut *mut u8) -> i32,
    allocate: impl FnOnce(usize) -> T,
) -> Result<T> {
    let len = encoder(ptr::null_mut());
    if len <= 0 {
        return Err(Error::capture());
    }
    let mut out = allocate(len as usize);
    let bytes = out.as_mut();
    let mut cursor = bytes.as_mut_ptr();
    if encoder(&mut cursor) != len || cursor != bytes.as_mut_ptr().wrapping_add(bytes.len()) {
        return Err(Error::InvalidState("inconsistent native encoding length"));
    }
    Ok(out)
}

// SAFETY: The encoder satisfies encode's bounded i2d contract.
#[cfg(any(backend = "openssl", backend = "libressl"))]
pub(crate) unsafe fn encode_secret(
    encoder: impl FnMut(*mut *mut u8) -> i32,
) -> Result<SecretBytes> {
    // SAFETY: Exactly sized secret storage is erased on every failure path.
    unsafe { encode_with(encoder, |len| SecretBytes::from(vec![0; len])) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoders_check_query_write_length_and_cursor() {
        // These encoders never exceed the queried capacity, including on error.
        for failure in [-1, 0] {
            assert!(unsafe { encode(|_| failure) }.is_err());
        }
        for (written, advance) in [(-1, 0), (1, 1), (2, 1), (2, 2)] {
            let result = unsafe {
                encode(|out| {
                    if out.is_null() {
                        return 2;
                    }
                    // The queried allocation is two bytes and remains live.
                    (*out).write_bytes(0x42, 2);
                    *out = (*out).add(advance);
                    written
                })
            };
            if written == 2 && advance == 2 {
                assert_eq!(result.unwrap(), [0x42; 2]);
            } else {
                assert!(result.is_err());
            }
        }
    }
}
