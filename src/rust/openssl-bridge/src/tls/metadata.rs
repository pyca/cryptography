use super::*;
use std::ffi::c_char;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CipherInfo {
    pub name: String,
    pub protocol: String,
    pub secret_bits: i32,
}
#[derive(Clone, Debug)]
pub struct ConnectionInfo {
    pub server_name: Option<Vec<u8>>,
    pub state: Vec<u8>,
    pub version: i32,
    pub version_name: String,
    pub cipher: Option<CipherInfo>,
    pub alpn: Vec<u8>,
    pub srtp: Option<Vec<u8>>,
    pub group: Option<String>,
    pub want_read: bool,
    pub want_write: bool,
}

// SAFETY contract: non-NULL pointers must refer to live terminated native text.
unsafe fn copied_text(value: *const c_char) -> Option<Vec<u8>> {
    if value.is_null() {
        None
    } else {
        // SAFETY: The caller guarantees native text storage remains live.
        Some(unsafe { CStr::from_ptr(value) }.to_bytes().to_vec())
    }
}
fn text_string(value: Option<Vec<u8>>) -> String {
    String::from_utf8_lossy(value.as_deref().unwrap_or_default()).into_owned()
}

// SAFETY contract: this SSL is live and exclusively in use on this thread.
// May also be called from a synchronous callback for that SSL; it performs only
// permitted native metadata queries and returns no borrowed native storage.
pub(super) unsafe fn snapshot(ssl: *mut ffi::SSL) -> ConnectionInfo {
    // SAFETY: All returned strings belong to the live SSL or immutable native
    // descriptors. Copy them before returning; no native operation can intervene.
    unsafe {
        let cipher = ffi::SSL_get_current_cipher(ssl);
        let cipher = if cipher.is_null() {
            None
        } else {
            Some(CipherInfo {
                name: text_string(copied_text(ffi::SSL_CIPHER_get_name(cipher))),
                protocol: text_string(copied_text(ffi::SSL_CIPHER_get_version(cipher))),
                secret_bits: ffi::SSL_CIPHER_get_bits(cipher, std::ptr::null_mut()),
            })
        };
        let mut alpn = std::ptr::null();
        let mut alpn_length = 0;
        ffi::SSL_get0_alpn_selected(ssl, &mut alpn, &mut alpn_length);
        let alpn = if alpn_length == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(alpn, alpn_length as usize).to_vec()
        };
        ConnectionInfo {
            server_name: copied_text(ffi::SSL_get_servername(
                ssl,
                ffi::TLSEXT_NAMETYPE_host_name as i32,
            )),
            state: copied_text(ffi::SSL_state_string_long(ssl)).unwrap_or_default(),
            version: ffi::SSL_version(ssl),
            version_name: text_string(copied_text(ffi::SSL_get_version(ssl))),
            cipher,
            alpn,
            srtp: copied_text(ffi::OB_tls_srtp(ssl)),
            group: copied_text(ffi::OB_tls_group(ssl)).map(|name| text_string(Some(name))),
            want_read: ffi::SSL_want(ssl) == ffi::SSL_READING as i32,
            want_write: ffi::SSL_want(ssl) == ffi::SSL_WRITING as i32,
        }
    }
}

// SAFETY contract: a live, immutable certificate decoded from DER, owned by the
// exclusive SSL or an immutable context/session. X509_dup copies its encoded
// ASN.1 value, without populating mutable extension/public-key caches on source.
pub(super) unsafe fn certificate_copy(raw: *mut ffi::X509) -> Result<Vec<u8>> {
    // SAFETY: The source is live through the independent deep copy.
    let mut owned = Certificate(pointer(unsafe { ffi::X509_dup(raw) })?);
    owned.encode(Encoding::Der)
}
// SAFETY contract: borrowed chain and its certificates stay live and immutable
// throughout this call. No caller-visible reference to any native object escapes.
pub(super) unsafe fn chain_copy(chain: *const ffi::stack_st_X509) -> Result<Vec<Vec<u8>>> {
    // SAFETY: The supplied stack is live or NULL; the shim handles either.
    let length = unsafe { ffi::OB_x509_stack_len(chain) };
    let mut result = Vec::with_capacity(length);
    for i in 0..length {
        // SAFETY: i is in bounds and the source certificates remain live.
        result.push(unsafe { certificate_copy(ffi::OB_x509_stack_get(chain, i)) }?);
    }
    Ok(result)
}

// SAFETY contract: names and their entries are live during this exclusive SSL
// operation or within the backend's permitted certificate selection callback.
pub(super) unsafe fn ca_names_copy(names: *const ffi::stack_st_X509_NAME) -> Result<Vec<Vec<u8>>> {
    // SAFETY: Each source name is borrowed only for a deep copy; the returned
    // encodings have independent ownership and no native cached state escapes.
    unsafe {
        let length = ffi::OB_x509_name_stack_len(names);
        (0..length)
            .map(|i| {
                let source = ffi::OB_x509_name_stack_get(names, i);
                let mut owned = crate::x509::Name(pointer(ffi::X509_NAME_dup(source))?);
                owned.der()
            })
            .collect()
    }
}

/// A session retains its factory and may only be resumed with that exact
/// factory. Sharing a session across independently configured trust policies is
/// rejected, even if the two contexts happen to hold the same certificate.
pub struct Session {
    native: NonNull<ffi::SSL_SESSION>,
    context: Context,
    credentials_context: Context,
    verification: PeerVerification,
    reference_identity: Option<Vec<u8>>,
    sni: Option<Vec<u8>>,
    role: Role,
    hooks: Arc<dyn Callbacks>,
}
impl Drop for Session {
    fn drop(&mut self) {
        // SAFETY: Release the reference acquired by SSL_get1_session exactly once.
        unsafe { ffi::SSL_SESSION_free(self.native.as_ptr()) };
    }
}
// SAFETY: The owned native session reference can move between threads. It has
// no mutable exported aliases or asynchronous state. Session is deliberately !Sync.
unsafe impl Send for Session {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShutdownState {
    Open,
    Sent,
    Received,
    Both,
}
impl Connection {
    pub fn info(&mut self) -> ConnectionInfo {
        // SAFETY: This method exclusively borrows a live, owned connection.
        unsafe { snapshot(self.native.0.as_ptr()) }
    }
    pub fn pending(&mut self) -> usize {
        // SAFETY: Exclusive live connection; copies pending plaintext byte count.
        unsafe { ffi::SSL_pending(self.native.0.as_ptr()) }.max(0) as usize
    }
    pub fn cipher_names(&mut self) -> Vec<String> {
        let mut result = Vec::new();
        for i in 0..65536 {
            // SAFETY: Native lookup checks index and returns NULL at end. Each
            // immutable descriptor string is copied during this exclusive call.
            let name = unsafe { copied_text(ffi::SSL_get_cipher_list(self.native.0.as_ptr(), i)) };
            match name {
                Some(name) => result.push(text_string(Some(name))),
                None => break,
            }
        }
        result
    }
    pub fn certificate_der(&mut self) -> Result<Option<Vec<u8>>> {
        // SAFETY: The installed certificate is an immutable independent decode;
        // the exclusive SSL retains its reference through the copy.
        unsafe {
            let certificate = ffi::SSL_get_certificate(self.native.0.as_ptr());
            if certificate.is_null() {
                Ok(None)
            } else {
                certificate_copy(certificate).map(Some)
            }
        }
    }
    pub fn peer_certificate_der(&mut self) -> Result<Option<Vec<u8>>> {
        // SAFETY: The getter acquires a reference. Deep-copy its immutable ASN.1
        // value before freeing that reference; no mutating caller alias escapes.
        unsafe {
            let Some(certificate) =
                NonNull::new(ffi::OB_tls_peer_certificate(self.native.0.as_ptr()))
            else {
                return Ok(None);
            };
            let owner = Certificate(certificate);
            certificate_copy(owner.0.as_ptr()).map(Some)
        }
    }
    pub fn peer_chain_der(&mut self) -> Result<Option<Vec<Vec<u8>>>> {
        // SAFETY: The borrowed chain is retained by the exclusive connection.
        unsafe {
            let chain = ffi::SSL_get_peer_cert_chain(self.native.0.as_ptr());
            if chain.is_null() {
                Ok(None)
            } else {
                chain_copy(chain).map(Some)
            }
        }
    }
    /// Return the chain native verification constructed. This is diagnostic
    /// data, not proof of peer authentication: verification can be disabled or
    /// explicitly overridden by an application callback.
    pub fn verification_chain_der(&mut self) -> Result<Option<Vec<Vec<u8>>>> {
        // SAFETY: The chain is borrowed from this exclusive SSL and copied now.
        unsafe {
            let chain = ffi::OB_tls_verified_chain(self.native.0.as_ptr());
            if chain.is_null() {
                Ok(callbacks::lock(&self.callbacks.records)
                    .verification_chain
                    .clone())
            } else {
                chain_copy(chain).map(Some)
            }
        }
    }
    pub fn client_ca_names_der(&mut self) -> Result<Vec<Vec<u8>>> {
        if self.role == Role::Server {
            return Ok(self.context.0.client_ca_names.clone());
        }
        if cfg!(any(backend = "boringssl", backend = "awslc")) {
            return Ok(callbacks::lock(&self.callbacks.records)
                .client_ca_names
                .clone());
        }
        // SAFETY: Client names came from decoded handshake bytes, remain owned
        // by this exclusively held SSL, and are copied before the next operation.
        unsafe {
            let names = ffi::SSL_get_client_CA_list(self.native.0.as_ptr());
            ca_names_copy(names)
        }
    }
    pub fn session(&mut self) -> Option<Session> {
        // SAFETY: Acquires an independently releasable reference, or NULL before
        // a session exists. The exact immutable originating context is retained.
        NonNull::new(unsafe { ffi::SSL_get1_session(self.native.0.as_ptr()) }).map(|native| {
            Session {
                native,
                context: self.initial_context.clone(),
                credentials_context: self.context.clone(),
                verification: self.verification,
                reference_identity: self.reference_identity.clone(),
                sni: self.sni.clone(),
                role: self.role,
                hooks: callbacks::lock(&self.callbacks.hooks).clone(),
            }
        })
    }
    pub fn set_session(&mut self, session: &mut Session) -> Result<()> {
        self.configuring()?;
        if !Arc::ptr_eq(&session.context.0, &self.initial_context.0)
            || !Arc::ptr_eq(&session.credentials_context.0, &self.context.0)
            || session.verification != self.verification
            || session.reference_identity != self.reference_identity
            || session.sni != self.sni
            || session.role != self.role
            || !Arc::ptr_eq(&session.hooks, &callbacks::lock(&self.callbacks.hooks))
        {
            return Err(Error::InvalidInput(
                "session belongs to a different TLS context or authentication policy",
            ));
        }
        // SAFETY: Exclusive connection and session; SSL retains its own session
        // reference. Context identity prevents crossing verification policies.
        check(unsafe { ffi::SSL_set_session(self.native.0.as_ptr(), session.native.as_ptr()) })?;
        self.session_installed = true;
        Ok(())
    }
    pub fn client_random(&mut self) -> Option<[u8; 32]> {
        self.random(false)
    }
    pub fn server_random(&mut self) -> Option<[u8; 32]> {
        self.random(true)
    }
    fn random(&mut self, server: bool) -> Option<[u8; 32]> {
        // SAFETY: All queries are within the exclusive SSL borrow. Native random
        // getters copy at most the supplied destination capacity.
        unsafe {
            if ffi::SSL_get_session(self.native.0.as_ptr()).is_null() {
                return None;
            }
            if let Some(random) =
                callbacks::lock(&self.callbacks.records).hello_randoms[usize::from(server)]
            {
                return Some(random);
            }
            let mut out = [0; 32];
            let length = if server {
                ffi::SSL_get_server_random(self.native.0.as_ptr(), out.as_mut_ptr(), out.len())
            } else {
                ffi::SSL_get_client_random(self.native.0.as_ptr(), out.as_mut_ptr(), out.len())
            };
            (length == 32).then_some(out)
        }
    }
    /// Export sensitive session material. Prefer a labeled TLS exporter for
    /// application binding; the legacy master secret can expose the connection.
    pub fn master_secret(&mut self) -> Result<Option<SecretBytes>> {
        // SAFETY: The session remains borrowed from this exclusive SSL; both
        // length query and bounded copy refer to the same immutable secret.
        unsafe {
            let session = ffi::SSL_get_session(self.native.0.as_ptr());
            if session.is_null() {
                return Ok(None);
            }
            let length = ffi::SSL_SESSION_get_master_key(session, std::ptr::null_mut(), 0);
            let mut out = SecretBytes::from(vec![0; length]);
            crate::error::check_len(
                ffi::SSL_SESSION_get_master_key(session, out.as_mut().as_mut_ptr(), length),
                length,
            )?;
            Ok(Some(out))
        }
    }
    pub fn export_keying_material(
        &mut self,
        label: &[u8],
        context: Option<&[u8]>,
        length: usize,
    ) -> Result<SecretBytes> {
        self.ready()?;
        if length > 65535 {
            return Err(Error::InvalidInput("exporter output exceeds 65535 bytes"));
        }
        let mut out = SecretBytes::from(vec![0; length]);
        let context_bytes = context.unwrap_or_default();
        // SAFETY: Exclusive SSL; each source/destination covers its length and
        // no pointer is retained. None and an empty context remain distinct.
        check(unsafe {
            ffi::SSL_export_keying_material(
                self.native.0.as_ptr(),
                out.as_mut().as_mut_ptr(),
                length,
                label.as_ptr().cast(),
                label.len(),
                context_bytes.as_ptr(),
                context_bytes.len(),
                i32::from(context.is_some()),
            )
        })?;
        Ok(out)
    }
    pub fn finished_message(&mut self, peer: bool) -> Vec<u8> {
        let captured = callbacks::lock(&self.callbacks.records).finished[usize::from(peer)].clone();
        if !captured.is_empty() {
            return captured;
        }
        // TLS Finished is at most a SHA-512 output. Native getters safely cap
        // their copy and return full length; truncate only within the bound.
        let mut out = [0; 64];
        // SAFETY: Exclusive SSL and writable fixed-capacity destination.
        let length = unsafe {
            if peer {
                ffi::SSL_get_peer_finished(
                    self.native.0.as_ptr(),
                    out.as_mut_ptr().cast(),
                    out.len(),
                )
            } else {
                ffi::SSL_get_finished(self.native.0.as_ptr(), out.as_mut_ptr().cast(), out.len())
            }
        };
        out[..length.min(out.len())].to_vec()
    }
    pub fn shutdown_state(&mut self) -> ShutdownState {
        // SAFETY: Exclusive live SSL; returns a copied shutdown bitmask.
        let bits = unsafe { ffi::SSL_get_shutdown(self.native.0.as_ptr()) } as u32;
        match (
            bits & ffi::SSL_SENT_SHUTDOWN != 0,
            bits & ffi::SSL_RECEIVED_SHUTDOWN != 0,
        ) {
            (false, false) => ShutdownState::Open,
            (true, false) => ShutdownState::Sent,
            (false, true) => ShutdownState::Received,
            (true, true) => ShutdownState::Both,
        }
    }
    /// Legacy transport bookkeeping. This does not send or authenticate a
    /// close_notify alert; callers remain responsible for their truncation policy.
    pub fn set_shutdown_state(&mut self, state: ShutdownState) -> Result<()> {
        self.ready()?;
        let bits = match state {
            ShutdownState::Open => 0,
            ShutdownState::Sent => ffi::SSL_SENT_SHUTDOWN,
            ShutdownState::Received => ffi::SSL_RECEIVED_SHUTDOWN,
            ShutdownState::Both => ffi::SSL_SENT_SHUTDOWN | ffi::SSL_RECEIVED_SHUTDOWN,
        };
        #[cfg(any(backend = "boringssl", backend = "awslc"))]
        {
            // These forks assert that shutdown is monotonic. Reject clearing
            // flags before entering C, including in debug native builds.
            // SAFETY: Read-only query of this exclusively borrowed connection.
            let previous = unsafe { ffi::SSL_get_shutdown(self.native.0.as_ptr()) } as u32;
            if previous & bits != previous {
                return Err(Error::InvalidInput(
                    "this backend cannot clear TLS shutdown flags",
                ));
            }
        }
        // SAFETY: Exclusive connection; documented bits and backend state rules
        // are validated above.
        unsafe { ffi::SSL_set_shutdown(self.native.0.as_ptr(), bits as i32) };
        Ok(())
    }
    pub fn request_renegotiation(&mut self) -> Result<bool> {
        self.ready()?;
        if self.pending_write.is_some() {
            return Err(Error::InvalidState(
                "retry the pending write before renegotiation",
            ));
        }
        #[cfg(any(backend = "boringssl", backend = "awslc"))]
        {
            Err(Error::Unsupported(
                "renegotiation is not supported by this backend",
            ))
        }
        #[cfg(not(any(backend = "boringssl", backend = "awslc")))]
        {
            if self.renegotiation_pending() {
                return Ok(false);
            }
            // SAFETY: Exclusive SSL with no outstanding write; native code checks
            // the negotiated version and whether renegotiation is permitted.
            check(unsafe { ffi::OB_tls_renegotiate(self.native.0.as_ptr()) })?;
            Ok(true)
        }
    }
    pub fn renegotiation_pending(&mut self) -> bool {
        // SAFETY: Exclusive live SSL query, returning only an integer flag.
        unsafe { ffi::OB_tls_renegotiate_pending(self.native.0.as_ptr()) != 0 }
    }
    pub fn total_renegotiations(&mut self) -> i64 {
        // SAFETY: Exclusive live SSL query, returning only a copied count.
        unsafe { ffi::OB_tls_total_renegotiations(self.native.0.as_ptr()) as i64 }
    }
}
