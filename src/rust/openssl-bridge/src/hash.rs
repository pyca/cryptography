use crate::{
    error::{check, pointer},
    ffi, Error, Result,
};
use std::{
    ffi::CString,
    ptr::{self, NonNull},
};

/// A backend-owned, immutable digest descriptor with process lifetime.
#[derive(Clone, Copy)]
pub struct Algorithm(NonNull<ffi::EVP_MD>);

// SAFETY: Descriptors returned by EVP_get_digestbyname are immutable globals.
unsafe impl Send for Algorithm {}
// SAFETY: No API exposed here mutates or frees a descriptor.
unsafe impl Sync for Algorithm {}

impl Algorithm {
    pub fn from_name(name: &str) -> Result<Self> {
        crate::initialize()?;
        let name =
            CString::new(name).map_err(|_| Error::InvalidInput("digest name contains NUL"))?;
        // SAFETY: name is a live, NUL-terminated string; lookup retains no borrow.
        let md = unsafe { ffi::EVP_get_digestbyname(name.as_ptr()) };
        NonNull::new(md.cast_mut())
            .map(Self)
            .ok_or(Error::Unsupported("unknown digest"))
    }

    pub fn output_size(self) -> Result<usize> {
        // SAFETY: self holds a live, immutable digest descriptor.
        let size = unsafe { ffi::OB_md_size(self.0.as_ptr()) };
        usize::try_from(size)
            .ok()
            .filter(|v| *v > 0)
            .ok_or(Error::Unsupported("digest has no fixed output size"))
    }

    pub fn block_size(self) -> Result<usize> {
        // SAFETY: self holds a live, immutable digest descriptor.
        let size = unsafe { ffi::OB_md_block_size(self.0.as_ptr()) };
        usize::try_from(size)
            .ok()
            .filter(|v| *v > 0)
            .ok_or(Error::Unsupported("digest has no block size"))
    }

    pub fn is_xof(self) -> bool {
        // SAFETY: self holds a live, immutable digest descriptor.
        unsafe { ffi::OB_md_is_xof(self.0.as_ptr()) != 0 }
    }

    pub(crate) fn as_ptr(self) -> *const ffi::EVP_MD {
        self.0.as_ptr()
    }
}

/// A streaming hash. Finalization consumes it and cloning is fallible.
///
/// ```compile_fail
/// use openssl_bridge::hash::{Algorithm, Hasher};
/// let mut hash = Hasher::new(Algorithm::from_name("sha256").unwrap()).unwrap();
/// hash.finish().unwrap();
/// hash.update(b"too late").unwrap();
/// ```
pub struct Hasher {
    ctx: NonNull<ffi::EVP_MD_CTX>,
    algorithm: Algorithm,
    poisoned: bool,
    squeezed: bool,
}

// SAFETY: The context is uniquely owned. Exclusive access is required to mutate it.
unsafe impl Send for Hasher {}
// SAFETY: Shared operations inspect or copy the context without modifying it.
unsafe impl Sync for Hasher {}

impl Hasher {
    pub fn new(algorithm: Algorithm) -> Result<Self> {
        // SAFETY: The allocator has no preconditions.
        let ctx = pointer(unsafe { ffi::EVP_MD_CTX_new() })?;
        let result = Self {
            ctx,
            algorithm,
            poisoned: false,
            squeezed: false,
        };
        // SAFETY: ctx is owned; algorithm is live; no engine is supplied.
        check(unsafe {
            ffi::EVP_DigestInit_ex(ctx.as_ptr(), algorithm.as_ptr(), ptr::null_mut())
        })?;
        Ok(result)
    }

    fn ready(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::InvalidState("hash context is poisoned"))
        } else {
            Ok(())
        }
    }

    pub fn update(&mut self, data: &[u8]) -> Result<()> {
        self.ready()?;
        if self.squeezed {
            return Err(Error::InvalidState("cannot absorb after squeezing"));
        }
        self.poisoned = true;
        // SAFETY: The initialized context is exclusive; data is readable for len.
        check(unsafe {
            ffi::EVP_DigestUpdate(self.ctx.as_ptr(), data.as_ptr().cast(), data.len())
        })?;
        self.poisoned = false;
        Ok(())
    }

    pub fn try_clone(&self) -> Result<Self> {
        self.ready()?;
        // SAFETY: The allocator has no preconditions.
        let ctx = pointer(unsafe { ffi::EVP_MD_CTX_new() })?;
        let result = Self {
            ctx,
            algorithm: self.algorithm,
            poisoned: false,
            squeezed: self.squeezed,
        };
        // SAFETY: The source is initialized; the destination is uniquely owned.
        check(unsafe { ffi::EVP_MD_CTX_copy_ex(ctx.as_ptr(), self.ctx.as_ptr()) })?;
        Ok(result)
    }

    pub fn finish(self) -> Result<Vec<u8>> {
        self.ready()?;
        if self.algorithm.is_xof() {
            return Err(Error::InvalidInput(
                "use finish_xof for extendable-output digests",
            ));
        }
        let mut output = vec![0; self.algorithm.output_size()?];
        let mut written = 0;
        // SAFETY: output has exactly the selected digest's output size. The
        // context is initialized and consumed by this method.
        check(unsafe {
            ffi::EVP_DigestFinal_ex(self.ctx.as_ptr(), output.as_mut_ptr(), &mut written)
        })?;
        if written as usize != output.len() {
            return Err(Error::InvalidState(
                "backend returned an unexpected digest length",
            ));
        }
        Ok(output)
    }

    #[cfg(any(backend = "openssl", backend = "awslc"))]
    pub fn finish_xof(self, output: &mut [u8]) -> Result<()> {
        self.ready()?;
        if self.squeezed {
            return Err(Error::InvalidState("cannot finalize after squeezing"));
        }
        if !self.algorithm.is_xof() {
            return Err(Error::InvalidInput(
                "digest is not an extendable-output function",
            ));
        }
        // SAFETY: output is writable for its declared size; the XOF context is
        // initialized, has not been finalized, and is consumed here.
        check(unsafe {
            ffi::EVP_DigestFinalXOF(self.ctx.as_ptr(), output.as_mut_ptr(), output.len())
        })
    }

    #[cfg(any(openssl_330, backend = "awslc"))]
    pub fn squeeze_xof(&mut self, output: &mut [u8]) -> Result<()> {
        self.ready()?;
        if !self.algorithm.is_xof() {
            return Err(Error::InvalidInput(
                "digest is not an extendable-output function",
            ));
        }
        self.poisoned = true;
        // SAFETY: The initialized XOF context is exclusively borrowed; output
        // is writable for its length. Squeezing prevents any subsequent absorb.
        check(unsafe {
            ffi::EVP_DigestSqueeze(self.ctx.as_ptr(), output.as_mut_ptr(), output.len())
        })?;
        self.poisoned = false;
        self.squeezed = true;
        Ok(())
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        // SAFETY: This is the unique owner; free accepts all initialization states.
        unsafe { ffi::EVP_MD_CTX_free(self.ctx.as_ptr()) };
    }
}

pub fn digest(algorithm: Algorithm, input: &[u8]) -> Result<Vec<u8>> {
    let mut context = Hasher::new(algorithm)?;
    context.update(input)?;
    context.finish()
}

#[cfg(any(backend = "openssl", backend = "awslc"))]
pub fn digest_xof(algorithm: Algorithm, input: &[u8], output: &mut [u8]) -> Result<()> {
    let mut context = Hasher::new(algorithm)?;
    context.update(input)?;
    context.finish_xof(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn poisoned_hash_cannot_resume_or_escape_through_clone() {
        let mut h = Hasher::new(Algorithm::from_name("SHA256").unwrap()).unwrap();
        h.poisoned = true;
        assert!(h.update(b"message").is_err());
        assert!(h.try_clone().is_err());
        assert!(h.finish().is_err());
    }
}
