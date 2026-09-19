use crate::ffi;
use std::{ffi::CStr, fmt};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeError {
    pub code: u64,
    pub library: i32,
    pub reason: i32,
    pub description: String,
    pub reason_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    Native(Vec<NativeError>),
    InvalidInput(&'static str),
    InvalidState(&'static str),
    Unsupported(&'static str),
}

impl Error {
    pub(crate) fn capture() -> Self {
        Self::Native(take_error_queue())
    }
}

/// Drain the calling thread's native diagnostic queue into owned records.
/// This is diagnostic state, not an indication that an operation succeeded.
// Error codes are c_ulong on OpenSSL and u32 on BoringSSL/AWS-LC.
#[allow(clippy::useless_conversion)]
pub fn take_error_queue() -> Vec<NativeError> {
    let mut errors = Vec::new();
    loop {
        // SAFETY: Reads and removes the calling thread's error queue entry.
        let code = unsafe { ffi::ERR_get_error() };
        if code == 0 {
            break;
        }
        let mut description = [0 as std::os::raw::c_char; 256];
        // SAFETY: The destination is writable for the supplied length.
        // ERR_error_string_n always NUL-terminates a nonempty destination.
        unsafe { ffi::ERR_error_string_n(code, description.as_mut_ptr(), description.len()) };
        // SAFETY: The buffer was NUL-terminated above and remains live.
        let description = unsafe { CStr::from_ptr(description.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: A successful lookup returns a backend-owned, NUL-terminated
        // static string. Copy it while it is available; NULL means unknown.
        let reason_text = unsafe {
            let text = ffi::ERR_reason_error_string(code);
            if text.is_null() {
                String::new()
            } else {
                CStr::from_ptr(text).to_string_lossy().into_owned()
            }
        };
        // SAFETY: The shim evaluates pure error-code macros on an integer.
        let (library, reason) = unsafe {
            (
                ffi::OB_err_lib(code.into()),
                ffi::OB_err_reason(code.into()),
            )
        };
        errors.push(NativeError {
            code: code.into(),
            library,
            reason,
            description,
            reason_text,
        });
    }
    errors
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Native(errors) if errors.is_empty() => {
                f.write_str("backend operation failed without an error queue entry")
            }
            Self::Native(errors) => {
                for (i, error) in errors.iter().enumerate() {
                    if i != 0 {
                        f.write_str("; ")?;
                    }
                    f.write_str(&error.description)?;
                }
                Ok(())
            }
            Self::InvalidInput(message)
            | Self::InvalidState(message)
            | Self::Unsupported(message) => f.write_str(message),
        }
    }
}
impl std::error::Error for Error {}

pub(crate) fn check(code: i32) -> Result<()> {
    if code == 1 {
        Ok(())
    } else {
        Err(Error::capture())
    }
}

/// Interpret native predicates that distinguish false from an internal error.
pub(crate) fn check_bool(code: i32) -> Result<bool> {
    match code {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(Error::capture()),
    }
}

pub(crate) fn verification_result(code: i32) -> Result<bool> {
    let verified = check_bool(code)?;
    if !verified {
        // Invalid signatures may leave diagnostics which must not leak into
        // the next operation on the calling thread.
        take_error_queue();
    }
    Ok(verified)
}

pub(crate) fn pointer<T>(ptr: *mut T) -> Result<std::ptr::NonNull<T>> {
    std::ptr::NonNull::new(ptr).ok_or_else(Error::capture)
}

/// Validate a native fixed-size output before exposing it to a caller.
pub(crate) fn check_len(actual: usize, expected: usize) -> Result<()> {
    if actual == expected {
        Ok(())
    } else {
        Err(Error::InvalidState(
            "backend returned an unexpected output length",
        ))
    }
}

/// Validate a native variable-size output against the caller's allocation.
pub(crate) fn check_len_at_most(actual: usize, capacity: usize) -> Result<()> {
    if actual <= capacity {
        Ok(())
    } else {
        Err(Error::InvalidState("backend output exceeded its capacity"))
    }
}

/// Check a Rust buffer length before passing it to a narrower native parameter.
pub(crate) fn input_length<T: TryFrom<usize>>(length: usize, message: &'static str) -> Result<T> {
    T::try_from(length).map_err(|_| Error::InvalidInput(message))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_lengths_reject_truncation_without_allocating_large_buffers() {
        assert_eq!(input_length::<i32>(0, "length").unwrap(), 0);
        assert_eq!(
            input_length::<i32>(i32::MAX as usize, "length").unwrap(),
            i32::MAX
        );
        assert_eq!(
            input_length::<i32>(i32::MAX as usize + 1, "length"),
            Err(Error::InvalidInput("length"))
        );
        assert_eq!(
            input_length::<usize>(usize::MAX, "length").unwrap(),
            usize::MAX
        );
        assert_eq!(input_length::<i64>(0, "length").unwrap(), 0);
        if usize::BITS == 64 {
            assert!(input_length::<i64>(usize::MAX, "length").is_err());
        }
    }

    #[test]
    fn native_lengths_are_checked_before_exposing_output() {
        for size in [0, 1, 16, usize::MAX] {
            assert!(check_len(size, size).is_ok());
            assert!(check_len_at_most(size, size).is_ok());
            assert!(check_len_at_most(0, size).is_ok());
        }
        assert!(check_len(15, 16).is_err());
        assert!(check_len(17, 16).is_err());
        assert!(check_len_at_most(17, 16).is_err());
        assert!(check_len_at_most(usize::MAX, 0).is_err());
    }

    #[test]
    fn diagnostic_queue_formats_multiple_records() {
        let record = NativeError {
            code: 0,
            library: 0,
            reason: 0,
            description: "failure".into(),
            reason_text: "failure".into(),
        };
        assert_eq!(
            Error::Native(vec![record.clone(), record]).to_string(),
            "failure; failure"
        );
    }

    #[test]
    fn native_predicates_preserve_internal_errors() {
        assert!(check_bool(1).unwrap());
        assert!(!check_bool(0).unwrap());
        assert!(matches!(check_bool(-1), Err(Error::Native(_))));
        assert!(verification_result(1).unwrap());
        assert!(!verification_result(0).unwrap());
        assert!(verification_result(-1).is_err());
    }
}
