use crate::ffi;
use std::{ffi::CStr, fmt};

pub type Result<T> = std::result::Result<T, Error>;

/// Drain the calling thread's native diagnostic queue into owned records.
/// This is diagnostic state, not an indication that an operation succeeded.
pub fn take_error_queue() -> Vec<NativeError> {
    match Error::capture() {
        Error::Native(errors) => errors,
        _ => unreachable!(),
    }
}

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
    // Error codes are c_ulong on OpenSSL and u32 on BoringSSL/AWS-LC.
    #[allow(clippy::useless_conversion)]
    pub(crate) fn capture() -> Self {
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
        Self::Native(errors)
    }
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

pub(crate) fn pointer<T>(ptr: *mut T) -> Result<std::ptr::NonNull<T>> {
    std::ptr::NonNull::new(ptr).ok_or_else(Error::capture)
}
