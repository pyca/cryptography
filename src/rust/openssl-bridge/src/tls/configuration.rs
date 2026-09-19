use super::*;
use crate::x509::Name;

fn alpn_wire(protocols: &[&[u8]]) -> Result<Vec<u8>> {
    let mut wire = Vec::new();
    for protocol in protocols {
        let length = u8::try_from(protocol.len())
            .map_err(|_| Error::InvalidInput("ALPN protocol exceeds 255 bytes"))?;
        if length == 0 {
            return Err(Error::InvalidInput("ALPN protocols must not be empty"));
        }
        if wire.len() + 1 + protocol.len() > 65535 {
            return Err(Error::InvalidInput(
                "ALPN list exceeds the TLS extension length",
            ));
        }
        wire.push(length);
        wire.extend_from_slice(protocol);
    }
    Ok(wire)
}

struct NameStack(NonNull<ffi::stack_st_X509_NAME>);
impl Drop for NameStack {
    fn drop(&mut self) {
        // SAFETY: Sole stack owner, including ownership of every pushed name.
        unsafe { ffi::OB_x509_name_stack_free(self.0.as_ptr()) };
    }
}
impl ContextBuilder {
    pub fn set_peer_verification(&mut self, policy: PeerVerification) {
        // SAFETY: Exclusively owned builder, no native operation in progress.
        unsafe {
            ffi::SSL_CTX_set_verify(
                self.native.0.as_ptr(),
                policy.bits(),
                Some(callbacks::verify),
            )
        };
        self.verification = policy;
    }
    pub fn verification(&self) -> PeerVerification {
        self.verification
    }
    pub fn set_verify_depth(&mut self, depth: u32) -> Result<()> {
        let depth = i32::try_from(depth)
            .map_err(|_| Error::InvalidInput("verification depth exceeds INT_MAX"))?;
        // SAFETY: Exclusive builder and nonnegative bounded depth.
        unsafe { ffi::SSL_CTX_set_verify_depth(self.native.0.as_ptr(), depth) };
        Ok(())
    }
    pub fn verify_depth(&mut self) -> i32 {
        // SAFETY: Exclusive builder; integer query has no retained references.
        unsafe { ffi::SSL_CTX_get_verify_depth(self.native.0.as_ptr()) }
    }
    pub fn set_session_id_context(&mut self, identifier: &[u8]) -> Result<()> {
        let length = u32::try_from(identifier.len())
            .map_err(|_| Error::InvalidInput("session identifier is too long"))?;
        // SAFETY: Native code validates its smaller limit and copies the slice.
        check(unsafe {
            ffi::SSL_CTX_set_session_id_context(
                self.native.0.as_ptr(),
                identifier.as_ptr(),
                length as _,
            )
        })
    }
    #[allow(clippy::useless_conversion)] // Native long is 32 bits on Windows.
    pub fn set_session_cache_mode(&mut self, mode: i64) -> Result<i64> {
        let mode = mode
            .try_into()
            .map_err(|_| Error::InvalidInput("session cache mode is out of range"))?;
        // SAFETY: Exclusive builder; no external cache callbacks are exposed.
        Ok(unsafe { ffi::OB_tls_context_set_cache_mode(self.native.0.as_ptr(), mode) } as i64)
    }
    pub fn session_cache_mode(&mut self) -> i64 {
        // SAFETY: Exclusive builder; returns only copied integer configuration.
        unsafe { ffi::OB_tls_context_cache_mode(self.native.0.as_ptr()) as i64 }
    }
    pub fn set_session_timeout(&mut self, seconds: u32) -> Result<()> {
        let seconds = i32::try_from(seconds)
            .map_err(|_| Error::InvalidInput("session timeout exceeds INT_MAX"))?;
        // SAFETY: Exclusive builder. Timeout fits every supported native long.
        unsafe { ffi::SSL_CTX_set_timeout(self.native.0.as_ptr(), seconds as _) };
        Ok(())
    }
    pub fn session_timeout(&mut self) -> i64 {
        // SAFETY: Exclusive builder; returns only copied integer configuration.
        unsafe { ffi::OB_tls_context_timeout(self.native.0.as_ptr()) as i64 }
    }
    pub fn set_groups(&mut self, groups: &CStr) -> Result<()> {
        // SAFETY: Exclusive builder; native parser validates and copies names.
        check(unsafe { ffi::OB_tls_context_groups(self.native.0.as_ptr(), groups.as_ptr()) })
    }
    pub fn set_tls13_ciphersuites(&mut self, names: &CStr) -> Result<()> {
        #[cfg(backend = "boringssl")]
        {
            let _ = names;
            Err(Error::Unsupported(
                "this backend does not configure TLS 1.3 cipher suites",
            ))
        }
        #[cfg(not(backend = "boringssl"))]
        {
            // SAFETY: Exclusive builder; terminated configuration is parsed/copied.
            check(unsafe { ffi::SSL_CTX_set_ciphersuites(self.native.0.as_ptr(), names.as_ptr()) })
        }
    }
    pub fn set_srtp_profiles(&mut self, profiles: &CStr) -> Result<()> {
        // SAFETY: Exclusive builder and terminated profile list, copied by SSL.
        match unsafe { ffi::OB_tls_context_srtp(self.native.0.as_ptr(), profiles.as_ptr()) } {
            0 => Ok(()),
            -1 => Err(Error::Unsupported("SRTP is disabled in this backend")),
            _ => Err(Error::capture()),
        }
    }
    pub fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()> {
        let wire = alpn_wire(protocols)?;
        // SAFETY: The validated length-prefixed list is copied synchronously.
        if unsafe {
            ffi::SSL_CTX_set_alpn_protos(self.native.0.as_ptr(), wire.as_ptr(), wire.len() as _)
        } == 0
        {
            Ok(())
        } else {
            Err(Error::capture())
        }
    }
    pub fn set_client_ca_names(&mut self, names: &[Vec<u8>]) -> Result<()> {
        self.check_ca_names_support(!names.is_empty(), self.max_version)?;
        // SAFETY: Creates a fresh empty stack owned by the guard until transfer.
        let stack = NameStack(pointer(unsafe { ffi::OB_x509_name_stack_new() })?);
        for der in names {
            let name = Name::from_der(der)?;
            // SAFETY: The decoded name transfers to the owned stack on success.
            check(unsafe { ffi::OB_x509_name_stack_push(stack.0.as_ptr(), name.0.as_ptr()) })?;
            std::mem::forget(name);
        }
        // SAFETY: Exclusive builder; setter takes ownership, releasing its old
        // stack. All input names are independent of caller-owned mutable X509s.
        unsafe { ffi::SSL_CTX_set_client_CA_list(self.native.0.as_ptr(), stack.0.as_ptr()) };
        std::mem::forget(stack);
        self.client_ca_names = names.to_vec();
        Ok(())
    }
    pub fn add_client_ca_certificate(&mut self, der: &[u8]) -> Result<()> {
        let mut certificate = Certificate::decode(der, Encoding::Der)?;
        let name = certificate.name(crate::x509::NameField::Subject)?.der()?;
        let mut names = self.client_ca_names.clone();
        names.push(name);
        self.set_client_ca_names(&names)
    }
    pub fn use_dh_parameters_pem(&mut self, pem: &[u8]) -> Result<()> {
        let bio = Bio::input(pem)?;
        // SAFETY: BIO owns the copied bytes. Only unencrypted public parameters
        // are accepted; a rejecting callback prevents terminal password prompts.
        let parameters = pointer(unsafe {
            ffi::PEM_read_bio_DHparams(
                bio.0.as_ptr(),
                std::ptr::null_mut(),
                Some(no_password),
                std::ptr::null_mut(),
            )
        })?;
        // SAFETY: Both pointers are live; SSL retains/copies the parameters on
        // success, and the decoder reference is freed on both outcomes.
        let result = unsafe {
            let result = ffi::OB_tls_context_dh(self.native.0.as_ptr(), parameters.as_ptr());
            ffi::DH_free(parameters.as_ptr());
            result
        };
        check(result)
    }
}
unsafe extern "C" fn no_password(
    _: *mut std::ffi::c_char,
    _: i32,
    _: i32,
    _: *mut std::ffi::c_void,
) -> i32 {
    0
}

impl Connection {
    pub fn set_options(&mut self, options: u64) -> Result<u64> {
        self.configuring()?;
        // SAFETY: Exclusive connection before any protocol operation begins.
        Ok(unsafe { ffi::OB_tls_set_options(self.native.0.as_ptr(), options) })
    }
    pub fn use_certificate_der(&mut self, der: &[u8]) -> Result<()> {
        self.configuring()?;
        let certificate = Certificate::decode(der, Encoding::Der)?;
        // SAFETY: Exclusive connection retains an independent decoded object.
        check(unsafe { ffi::SSL_use_certificate(self.native.0.as_ptr(), certificate.0.as_ptr()) })
    }
    pub fn use_private_key_der(&mut self, der: &[u8]) -> Result<()> {
        self.configuring()?;
        let key = Key::private_der(der)?;
        // SAFETY: Exclusive connection retains a fresh decoder's reference.
        check(unsafe { ffi::SSL_use_PrivateKey(self.native.0.as_ptr(), key.0.as_ptr()) })
    }
    pub fn set_alpn_protocols(&mut self, protocols: &[&[u8]]) -> Result<()> {
        self.configuring()?;
        let wire = alpn_wire(protocols)?;
        // SAFETY: The validated wire list is synchronously copied by SSL.
        if unsafe {
            ffi::SSL_set_alpn_protos(self.native.0.as_ptr(), wire.as_ptr(), wire.len() as _)
        } == 0
        {
            Ok(())
        } else {
            Err(Error::capture())
        }
    }
}
