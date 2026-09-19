//! TLS ownership and state transitions.
//!
//! A builder is exclusively mutable and consumed into an immutable factory.
//! Each connection owns its SSL object and transport. No raw handle is public.
use crate::{
    error::{check, pointer},
    ffi,
    secret::SecretBytes,
    x509::{Bio, Certificate, Encoding, Key, TrustStore},
    Error, Result,
};
use std::{ffi::CStr, ptr::NonNull, sync::Arc};

mod callbacks;
mod configuration;
mod datagram;
pub use callbacks::Callbacks;
mod metadata;
pub use metadata::{CipherInfo, ConnectionInfo, Session, ShutdownState};

/// Selected header constants for language compatibility adapters. Native
/// objects, allocation ownership, and pointers remain inside this abstraction.
pub fn compatibility_constants() -> Vec<(String, i64)> {
    // SAFETY: The shim's immutable generated table has static lifetime. Names
    // are terminated ASCII C identifiers, and both accessors bounds-check.
    unsafe {
        (0..ffi::OB_tls_constant_count())
            .map(|i| {
                (
                    CStr::from_ptr(ffi::OB_tls_constant_name(i))
                        .to_string_lossy()
                        .into_owned(),
                    ffi::OB_tls_constant_value(i),
                )
            })
            .collect()
    }
}

pub fn version_description(selector: i32) -> Vec<u8> {
    // SAFETY: OpenSSL_version returns immutable static text, including for an
    // unknown selector. Copy immediately without exposing the native pointer.
    unsafe {
        CStr::from_ptr(ffi::OpenSSL_version(selector))
            .to_bytes()
            .to_vec()
    }
}

pub fn default_verify_paths() -> (Vec<u8>, Vec<u8>) {
    // SAFETY: These getters return immutable, terminated build-time defaults.
    unsafe {
        (
            CStr::from_ptr(ffi::X509_get_default_cert_file())
                .to_bytes()
                .to_vec(),
            CStr::from_ptr(ffi::X509_get_default_cert_dir())
                .to_bytes()
                .to_vec(),
        )
    }
}

#[cfg(test)]
mod state_tests {
    use super::*;

    fn context(protocol: Protocol) -> Context {
        ContextBuilder::new(protocol, PeerVerification::None)
            .unwrap()
            .finish()
    }

    #[test]
    fn certificate_retry_preserves_writes_but_fatal_errors_erase_them() {
        let mut connection = Connection::memory(context(Protocol::Tls), Role::Client).unwrap();
        connection.pending_write = Some(b"pending plaintext".to_vec().into());
        assert!(matches!(
            connection.classify_status(ffi::SSL_ERROR_WANT_X509_LOOKUP, -1, None),
            Err(IoError::WantCertificate)
        ));
        assert!(connection.pending_write.is_some());
        assert!(!connection.poisoned);
        assert!(matches!(
            connection.classify_status(ffi::SSL_ERROR_SYSCALL, -1, Some(0)),
            Err(IoError::System { code: None, .. })
        ));
        assert!(connection.pending_write.is_none());
        assert!(connection.write(b"pending plaintext").is_err());
    }

    #[test]
    fn transports_and_pending_writes_restrict_operations() {
        let dtls = context(Protocol::Dtls);
        assert!(Connection::memory(dtls.clone(), Role::Client).is_err());
        let tls = context(Protocol::Tls);
        assert!(Connection::datagrams(tls.clone(), Role::Client, 1200).is_err());
        let mut stream = Connection::memory(tls, Role::Client).unwrap();
        assert_eq!(stream.context().protocol(), Protocol::Tls);
        assert_eq!(stream.role(), Role::Client);
        assert!(stream.set_sni(c"").is_err());
        assert!(stream.set_reference_dns_name(c"").is_err());
        assert!(stream.set_reference_dns_name(c"example.com").is_err());
        assert!(stream.set_context(context(Protocol::Dtls)).is_err());
        stream.set_context(context(Protocol::Tls)).unwrap();
        let policy = PeerVerification::Chain {
            require_certificate: false,
            once: false,
        };
        stream.set_peer_verification(policy).unwrap();
        assert_eq!(stream.verification(), policy);
        stream.set_reference_dns_name(c"example.com").unwrap();
        assert!(stream
            .set_peer_verification(PeerVerification::None)
            .is_err());
        assert_eq!(stream.write(&[]).unwrap(), 0);
        assert_eq!(stream.read(&mut [], false).unwrap(), 0);
        assert_eq!(stream.feed_ciphertext(&[]).unwrap(), 0);
        assert_eq!(stream.drain_ciphertext(&mut []).unwrap(), 0);
        assert!(stream.dtls_timeout().is_err());
        assert!(stream.dtls_handle_timeout().is_err());
        assert!(stream.dtls_listen().is_err());
        assert!(stream
            .export_keying_material(b"label", None, 65536)
            .is_err());
        assert!(stream.dtls_data_mtu().is_err());
        assert!(stream.set_ciphertext_mtu(1200).is_err());
        // A pending native write owns its original bytes. These guards must
        // prevent any operation which would invalidate that retry contract.
        stream.pending_write = Some(b"pending".to_vec().into());
        stream.write_wants_write = true;
        assert!(stream.read(&mut [0; 1], false).is_err());
        assert!(stream.set_ciphertext_mtu(1200).is_err());
        assert!(stream.request_renegotiation().is_err());
        assert!(stream.dtls_handle_timeout().is_err());

        let mut packets = Connection::datagrams(dtls, Role::Client, 1200).unwrap();
        assert!(packets.dtls_listen().is_err());
        assert!(packets.dtls_data_mtu().is_err());
        packets.set_ciphertext_mtu(1400).unwrap();
        assert!(packets.dtls_timeout().unwrap().is_none());
        assert!(!packets.dtls_handle_timeout().unwrap());
        packets.input_eof().unwrap();
        assert!(packets.feed_ciphertext(b"after EOF").is_err());
    }

    #[test]
    fn context_configuration_checks_modes_and_owned_inputs() {
        let mut builder = ContextBuilder::new(Protocol::Tls, PeerVerification::None).unwrap();
        assert!(builder.set_modes(u64::MAX).is_err());
        assert!(builder.clear_modes(u64::MAX).is_err());
        assert!(builder.add_crl_der(b"invalid").is_err());
        builder.set_verification_flags(0).unwrap();
        builder.set_default_verify_paths().unwrap();
        assert!(builder.set_srtp_profiles(c"not-a-profile").is_err());
        assert!(builder.use_dh_parameters_pem(b"invalid").is_err());
        #[cfg(any(backend = "boringssl", backend = "awslc"))]
        assert!(builder.enable_cookie_callbacks().is_err());
        builder.set_max_version(ffi::TLS1_2_VERSION as i32).unwrap();
        builder.set_client_ca_names(&[]).unwrap();
        assert!(builder.set_client_ca_names(&[b"invalid".to_vec()]).is_err());
    }

    #[test]
    fn memory_output_distinguishes_retry_from_transport_eof() {
        let mut connection = Connection::memory(context(Protocol::Tls), Role::Client).unwrap();
        assert!(matches!(
            connection.drain_ciphertext(&mut [0; 1]),
            Err(IoError::WantRead)
        ));
        let Transport::Memory { output, .. } = connection.transport else {
            // Failure-only test diagnostic.
            // NO-COVERAGE-START
            unreachable!()
            // NO-COVERAGE-END
        };
        // SAFETY: The connection owns this memory BIO exclusively. Requesting
        // its documented EOF result safely exercises a terminal transport error.
        unsafe { ffi::OB_bio_eof_return(output.as_ptr(), 0) };
        assert!(matches!(
            connection.drain_ciphertext(&mut [0; 1]),
            Err(IoError::Failure(Error::Native(_)))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn socket_transport_rejects_memory_bio_operations_and_dtls() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        let (socket, _peer) = UnixStream::pair().unwrap();
        assert!(Connection::socket(
            context(Protocol::Dtls),
            Role::Client,
            SocketTransport::duplicate(socket.as_raw_fd()).unwrap()
        )
        .is_err());
        let (socket, _peer) = UnixStream::pair().unwrap();
        let mut connection = Connection::socket(
            context(Protocol::Tls),
            Role::Client,
            SocketTransport::duplicate(socket.as_raw_fd()).unwrap(),
        )
        .unwrap();
        assert!(connection.feed_ciphertext(b"packet").is_err());
        assert!(connection.drain_ciphertext(&mut [0; 32]).is_err());
        assert!(connection.input_eof().is_err());
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Tls,
    Dtls,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Role {
    Client,
    Server,
}

/// Explicit peer authentication policy. Chain verification alone does not bind
/// a server to a DNS name; clients must also configure a reference identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerVerification {
    None,
    Chain {
        require_certificate: bool,
        once: bool,
    },
}
impl PeerVerification {
    fn bits(self) -> i32 {
        match self {
            Self::None => ffi::SSL_VERIFY_NONE as i32,
            Self::Chain {
                require_certificate,
                once,
            } => {
                ffi::SSL_VERIFY_PEER as i32
                    | if require_certificate {
                        ffi::SSL_VERIFY_FAIL_IF_NO_PEER_CERT as i32
                    } else {
                        0
                    }
                    | if once {
                        ffi::SSL_VERIFY_CLIENT_ONCE as i32
                    } else {
                        0
                    }
            }
        }
    }
}

struct NativeContext(NonNull<ffi::SSL_CTX>);
impl Drop for NativeContext {
    fn drop(&mut self) {
        // SAFETY: Release this owner's native context reference exactly once.
        unsafe { ffi::SSL_CTX_free(self.0.as_ptr()) };
    }
}
// SAFETY: Context ownership may move between threads; builders are not Sync.
unsafe impl Send for NativeContext {}

pub struct ContextBuilder {
    native: NativeContext,
    protocol: Protocol,
    max_version: i32,
    verification: PeerVerification,
    certificate_der: Option<Vec<u8>>,
    client_ca_names: Vec<Vec<u8>>,
}

struct ContextInner {
    native: NativeContext,
    protocol: Protocol,
    verification: PeerVerification,
    certificate_der: Option<Vec<u8>>,
    client_ca_names: Vec<Vec<u8>>,
}
// SAFETY: The factory is permanently frozen before sharing. OpenSSL and its
// forks support concurrent SSL_new calls and use of independently owned SSLs
// from an immutable SSL_CTX. No mutable store or certificate alias is exposed.
unsafe impl Sync for ContextInner {}

#[derive(Clone)]
pub struct Context(Arc<ContextInner>);

impl Context {
    pub fn protocol(&self) -> Protocol {
        self.0.protocol
    }
    pub fn verification(&self) -> PeerVerification {
        self.0.verification
    }
    pub fn certificate_der(&self) -> Option<&[u8]> {
        self.0.certificate_der.as_deref()
    }
    /// Verify using this frozen factory's trust configuration, returning owned
    /// certificate encodings. No mutable store reference is exposed.
    pub fn verify_certificate(
        &self,
        leaf: &[u8],
        chain: &[Vec<u8>],
    ) -> std::result::Result<Vec<Vec<u8>>, crate::x509::VerificationError> {
        // SAFETY: The factory's store configuration is permanently frozen.
        // As with independent SSL handshakes from a shared SSL_CTX, native
        // verification uses a fresh X509_STORE_CTX and synchronized store
        // lookups. The temporary guard is used only for verification, never
        // for changing trust settings or exporting any shared native object.
        let mut store = unsafe {
            let store = pointer(ffi::SSL_CTX_get_cert_store(self.0.native.0.as_ptr()))?;
            check(ffi::X509_STORE_up_ref(store.as_ptr()))?;
            TrustStore(store)
        };
        store.verify(leaf, chain)
    }
}

impl ContextBuilder {
    pub fn new(protocol: Protocol, verification: PeerVerification) -> Result<Self> {
        crate::initialize()?;
        // SAFETY: TLS initialization is internally synchronized; no callbacks or
        // application-owned configuration pointer is provided.
        check(unsafe { ffi::OPENSSL_init_ssl(0, std::ptr::null()) })?;
        // SAFETY: Each method is an immutable native static descriptor.
        let method = unsafe {
            match protocol {
                Protocol::Tls => ffi::TLS_method(),
                Protocol::Dtls => ffi::DTLS_method(),
            }
        };
        // SAFETY: A valid method descriptor creates a fresh owned factory.
        let native = NativeContext(pointer(unsafe { ffi::SSL_CTX_new(method) })?);
        callbacks::install(&native, verification)?;
        Ok(Self {
            native,
            protocol,
            max_version: 0,
            verification,
            certificate_der: None,
            client_ca_names: Vec::new(),
        })
    }
    /// Finish configuration. No API on Context can mutate native factory
    /// settings, certificates, callbacks, or its trust store after this point.
    pub fn finish(self) -> Context {
        Context(Arc::new(ContextInner {
            native: self.native,
            protocol: self.protocol,
            verification: self.verification,
            certificate_der: self.certificate_der,
            client_ca_names: self.client_ca_names,
        }))
    }
    pub fn set_options(&mut self, options: u64) -> u64 {
        // SAFETY: Exclusive configuration; options contain only native flags.
        unsafe { ffi::OB_tls_context_set_options(self.native.0.as_ptr(), options) }
    }
    pub fn set_modes(&mut self, modes: u64) -> Result<u64> {
        validate_modes(modes)?;
        // SAFETY: Only synchronous modes with supported lifetime contracts pass.
        Ok(unsafe { ffi::OB_tls_context_set_mode(self.native.0.as_ptr(), modes) })
    }
    pub fn clear_modes(&mut self, modes: u64) -> Result<u64> {
        validate_modes(modes)?;
        // SAFETY: Exclusive factory and supported synchronous mode flags.
        Ok(unsafe { ffi::OB_tls_context_clear_mode(self.native.0.as_ptr(), modes) })
    }
    pub fn set_min_version(&mut self, version: i32) -> Result<()> {
        // SAFETY: Exclusive factory; native code validates the version integer.
        check(unsafe { ffi::OB_tls_context_min_version(self.native.0.as_ptr(), version) })
    }
    pub fn set_max_version(&mut self, version: i32) -> Result<()> {
        self.check_ca_names_support(!self.client_ca_names.is_empty(), version)?;
        // SAFETY: Exclusive factory; native code validates the version integer.
        check(unsafe { ffi::OB_tls_context_max_version(self.native.0.as_ptr(), version) })?;
        self.max_version = version;
        Ok(())
    }
    fn check_ca_names_support(&self, has_names: bool, maximum: i32) -> Result<()> {
        if cfg!(backend = "libressl")
            && self.protocol == Protocol::Tls
            && has_names
            && (maximum == 0 || maximum > ffi::TLS1_2_VERSION as i32)
        {
            return Err(Error::Unsupported(
                "LibreSSL does not send TLS 1.3 CA names; explicitly select TLS 1.2 or omit CA hints",
            ));
        }
        Ok(())
    }
    pub fn set_cipher_list(&mut self, ciphers: &CStr) -> Result<()> {
        // SAFETY: The list is NUL-terminated and synchronously parsed/copied.
        check(unsafe { ffi::SSL_CTX_set_cipher_list(self.native.0.as_ptr(), ciphers.as_ptr()) })
    }
    pub fn use_certificate_der(&mut self, der: &[u8]) -> Result<()> {
        let mut certificate = Certificate::decode(der, Encoding::Der)?;
        let encoded = certificate.encode(Encoding::Der)?;
        // SAFETY: The native factory retains its own reference to an independent
        // decoded certificate, never an alias of a mutable caller-owned object.
        check(unsafe {
            ffi::SSL_CTX_use_certificate(self.native.0.as_ptr(), certificate.0.as_ptr())
        })?;
        self.certificate_der = Some(encoded);
        Ok(())
    }
    pub fn add_chain_certificate_der(&mut self, der: &[u8]) -> Result<()> {
        let certificate = Certificate::decode(der, Encoding::Der)?;
        // SAFETY: On success add_extra_chain_cert takes ownership; on failure
        // the local owner frees the certificate. No Rust pointer escapes.
        check(unsafe {
            ffi::OB_tls_context_add_chain_cert(self.native.0.as_ptr(), certificate.0.as_ptr())
            // A valid owned certificate is transferred here; this edge requires native
            // reference/allocation failure.
            // NO-COVERAGE-START
        })?;
        // NO-COVERAGE-END
        std::mem::forget(certificate);
        Ok(())
    }
    pub fn use_private_key_der(&mut self, der: &[u8]) -> Result<()> {
        let key = Key::private_der(der)?;
        // SAFETY: The factory retains its own reference to a freshly decoded
        // key. The local decoder reference is released on success and failure.
        check(unsafe { ffi::SSL_CTX_use_PrivateKey(self.native.0.as_ptr(), key.0.as_ptr()) })
    }
    pub fn check_private_key(&mut self) -> Result<()> {
        // SAFETY: Exclusive factory; checks the installed key/certificate pair.
        check(unsafe { ffi::SSL_CTX_check_private_key(self.native.0.as_ptr()) })
    }
    fn with_store<T>(&mut self, operation: impl FnOnce(&mut TrustStore) -> Result<T>) -> Result<T> {
        // SAFETY: The builder cannot have produced connections yet and its
        // native store has no exported aliases. Retain a temporary reference
        // while calling the owned store interface; it never escapes the closure.
        let mut store = unsafe {
            let store = pointer(ffi::SSL_CTX_get_cert_store(self.native.0.as_ptr()))?;
            check(ffi::X509_STORE_up_ref(store.as_ptr()))?;
            TrustStore(store)
        };
        operation(&mut store)
    }
    pub fn add_trusted_certificate_der(&mut self, der: &[u8]) -> Result<()> {
        self.with_store(|store| store.add_certificate_der(der))
    }
    pub fn add_crl_der(&mut self, der: &[u8]) -> Result<()> {
        self.with_store(|store| store.add_crl_der(der))
    }
    pub fn set_verification_flags(&mut self, flags: u64) -> Result<()> {
        self.with_store(|store| store.set_flags(flags))
    }
    pub fn set_verification_time(&mut self, time: i64) -> Result<()> {
        self.with_store(|store| store.set_time(time))
    }
    pub fn load_verify_locations(
        &mut self,
        file: Option<&CStr>,
        directory: Option<&CStr>,
    ) -> Result<()> {
        self.with_store(|store| store.load_locations(file, directory))
    }
    pub fn set_default_verify_paths(&mut self) -> Result<()> {
        // SAFETY: The native lookup mutates only the exclusively held factory's
        // store and copies any environment configuration it retains.
        check(unsafe { ffi::SSL_CTX_set_default_verify_paths(self.native.0.as_ptr()) })
    }
    pub fn verify_certificate(
        &mut self,
        leaf: &[u8],
        chain: &[Vec<u8>],
    ) -> std::result::Result<Vec<Vec<u8>>, crate::x509::VerificationError> {
        self.with_store(|store| Ok(store.verify(leaf, chain)))?
    }
}

fn validate_modes(modes: u64) -> Result<()> {
    let supported = (ffi::SSL_MODE_ENABLE_PARTIAL_WRITE
        | ffi::SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER
        | ffi::SSL_MODE_AUTO_RETRY
        | ffi::SSL_MODE_RELEASE_BUFFERS) as u64;
    if modes & !supported != 0 {
        return Err(Error::Unsupported(
            "TLS mode has unsupported lifetime or asynchronous requirements",
        ));
    }
    Ok(())
}

/// A duplicated socket descriptor owned independently of the caller. Available
/// on Unix; the memory transport does not require an operating-system handle.
pub struct SocketTransport {
    descriptor: i32,
}
impl SocketTransport {
    #[cfg(unix)]
    pub fn duplicate(descriptor: i32) -> std::io::Result<Self> {
        // SAFETY: fcntl validates an integer descriptor and returns a fresh
        // owned descriptor. No Python-returned integer is assumed to be owned.
        let descriptor = unsafe { ffi::OB_dup_socket(descriptor) };
        if descriptor < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Self { descriptor })
        }
    }
}
impl Drop for SocketTransport {
    fn drop(&mut self) {
        // SAFETY: This descriptor was freshly duplicated and is closed once.
        unsafe { ffi::OB_close_socket(self.descriptor) };
    }
}

struct NativeConnection(NonNull<ffi::SSL>);
impl Drop for NativeConnection {
    fn drop(&mut self) {
        // SAFETY: Sole SSL owner. Native BIOs belong to SSL after set_bio.
        unsafe { ffi::SSL_free(self.0.as_ptr()) };
    }
}
// SAFETY: A uniquely owned, synchronous SSL can move between threads between
// operations. Async engine modes are rejected; there is no Sync implementation.
unsafe impl Send for NativeConnection {}

enum Transport {
    Datagrams {
        input: datagram::Queue,
        output: datagram::Queue,
        mtu: u32,
        listen_complete: bool,
        listening: bool,
    },
    Memory {
        input: NonNull<ffi::BIO>,
        output: NonNull<ffi::BIO>,
    },
    Socket {
        _socket: SocketTransport,
    },
}
// SAFETY: Memory BIOs are solely owned by this connection's SSL. SocketTransport
// owns a duplicated descriptor. Neither variant exports a shared mutable handle.
unsafe impl Send for Transport {}

pub struct Connection {
    // Drop SSL before releasing the transport descriptor or context references.
    native: NativeConnection,
    transport: Transport,
    callbacks: Arc<callbacks::CallbackState>,
    initial_context: Context,
    reference_identity: Option<Vec<u8>>,
    sni: Option<Vec<u8>>,
    session_installed: bool,
    verification: PeerVerification,
    context: Context,
    role: Role,
    started: bool,
    poisoned: bool,
    pending_write: Option<SecretBytes>,
    write_wants_write: bool,
    input_closed: bool,
}

#[derive(Debug)]
pub enum IoError {
    WantRead,
    WantWrite,
    WantCertificate,
    Closed,
    System { code: Option<i32>, native: Error },
    Failure(Error),
}
pub type IoResult<T> = std::result::Result<T, IoError>;
impl From<Error> for IoError {
    fn from(error: Error) -> Self {
        Self::Failure(error)
    }
}

impl Connection {
    fn allocate(context: &Context, role: Role) -> Result<NativeConnection> {
        // SAFETY: The immutable factory outlives the returned SSL and supports
        // creating independent connections; SSL_new acquires its own context ref.
        let native = NativeConnection(pointer(unsafe {
            ffi::SSL_new(context.0.native.0.as_ptr())
        })?);
        // SAFETY: New exclusive SSL; configure role and synchronous retry mode.
        unsafe {
            match role {
                Role::Client => ffi::SSL_set_connect_state(native.0.as_ptr()),
                Role::Server => ffi::SSL_set_accept_state(native.0.as_ptr()),
            }
            ffi::OB_tls_set_mode(native.0.as_ptr(), ffi::SSL_MODE_AUTO_RETRY as u64);
        }
        Ok(native)
    }
    /// Construct a stream TLS connection over owned memory BIOs. DTLS requires
    /// a datagram transport with explicit packet boundaries and an MTU.
    pub fn memory(context: Context, role: Role) -> Result<Self> {
        if context.0.protocol != Protocol::Tls {
            return Err(Error::Unsupported("DTLS requires a datagram transport"));
        }
        let native = Self::allocate(&context, role)?;
        let input = Bio::memory()?;
        let output = Bio::memory()?;
        let transport = Transport::Memory {
            input: input.0,
            output: output.0,
        };
        // SAFETY: Distinct unchained BIOs transfer their sole references to the
        // SSL exactly once. Raw borrows stay tied to this connection's lifetime.
        unsafe { ffi::SSL_set_bio(native.0.as_ptr(), input.0.as_ptr(), output.0.as_ptr()) };
        std::mem::forget(input);
        std::mem::forget(output);
        let callbacks = callbacks::CallbackState::new(context.clone());
        callbacks.attach(&native)?;
        Ok(Self {
            native,
            transport,
            callbacks,
            initial_context: context.clone(),
            reference_identity: None,
            sni: None,
            session_installed: false,
            verification: context.verification(),
            context,
            role,
            started: false,
            poisoned: false,
            pending_write: None,
            write_wants_write: false,
            input_closed: false,
        })
    }
    pub fn socket(context: Context, role: Role, socket: SocketTransport) -> Result<Self> {
        if context.0.protocol != Protocol::Tls {
            return Err(Error::Unsupported("DTLS requires a datagram transport"));
        }
        let native = Self::allocate(&context, role)?;
        // SAFETY: The duplicated descriptor stays live until after SSL_free.
        // SSL's socket BIO uses BIO_NOCLOSE, leaving descriptor ownership here.
        check(unsafe { ffi::SSL_set_fd(native.0.as_ptr(), socket.descriptor) })?;
        let callbacks = callbacks::CallbackState::new(context.clone());
        callbacks.attach(&native)?;
        Ok(Self {
            native,
            transport: Transport::Socket { _socket: socket },
            callbacks,
            initial_context: context.clone(),
            reference_identity: None,
            sni: None,
            session_installed: false,
            verification: context.verification(),
            context,
            role,
            started: false,
            poisoned: false,
            pending_write: None,
            write_wants_write: false,
            input_closed: false,
        })
    }
    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn role(&self) -> Role {
        self.role
    }
    fn configuring(&self) -> Result<()> {
        if self.session_installed {
            return Err(Error::InvalidState(
                "configure the connection before installing a session",
            ));
        }
        if self.started {
            Err(Error::InvalidState(
                "TLS connection configuration is frozen after I/O starts",
            ))
        } else {
            Ok(())
        }
    }
    fn ready(&self) -> Result<()> {
        if self.poisoned {
            Err(Error::InvalidState(
                "TLS connection failed and cannot perform further I/O",
            ))
        } else {
            Ok(())
        }
    }
    pub fn set_role(&mut self, role: Role) -> Result<()> {
        self.configuring()?;
        // SAFETY: Exclusive connection with no handshake or outstanding I/O.
        unsafe {
            match role {
                Role::Client => ffi::SSL_set_connect_state(self.native.0.as_ptr()),
                Role::Server => ffi::SSL_set_accept_state(self.native.0.as_ptr()),
            }
        }
        self.role = role;
        Ok(())
    }
    /// Set the SNI extension. This does not enable certificate name validation.
    pub fn set_sni(&mut self, name: &CStr) -> Result<()> {
        self.configuring()?;
        if name.to_bytes().is_empty() {
            return Err(Error::InvalidInput("SNI name must not be empty"));
        }
        // SAFETY: Exclusive connection and a terminated name copied by native TLS.
        check(unsafe { ffi::OB_tls_set_server_name(self.native.0.as_ptr(), name.as_ptr()) })?;
        self.sni = Some(name.to_bytes().to_vec());
        Ok(())
    }
    /// Bind chain verification to a nonempty reference DNS identity. SNI remains
    /// a separate setting because the authenticated identity need not be sent.
    pub fn set_reference_dns_name(&mut self, name: &CStr) -> Result<()> {
        self.configuring()?;
        if name.to_bytes().is_empty() {
            return Err(Error::InvalidInput("reference identity must not be empty"));
        }
        if self.verification == PeerVerification::None {
            return Err(Error::InvalidState(
                "reference identities require peer verification",
            ));
        }
        // SAFETY: The borrowed parameters remain inside this exclusive method.
        // The native setter copies the supplied readable name bytes.
        unsafe {
            let param = pointer(ffi::SSL_get0_param(self.native.0.as_ptr()))?;
            check(ffi::X509_VERIFY_PARAM_set1_host(
                param.as_ptr(),
                name.as_ptr(),
                name.to_bytes().len(),
            ))?;
        }
        self.reference_identity = Some(name.to_bytes().to_vec());
        Ok(())
    }
    fn begin_io(&mut self) {
        if let Transport::Datagrams { listening, .. } = &mut self.transport {
            *listening = false;
        }
        self.started = true;
        // SAFETY: Clear only the initiating thread's queue/errno immediately
        // before I/O. Native error classification occurs on this same thread.
        unsafe {
            ffi::ERR_clear_error();
            ffi::OB_clear_errno();
        }
    }
    fn classify(&mut self, result: i32, errno: Option<i32>) -> IoResult<usize> {
        // SAFETY: No OpenSSL call has intervened since the I/O operation. This
        // uses the same exclusive SSL and the same thread's diagnostic queue.
        let kind = unsafe { ffi::SSL_get_error(self.native.0.as_ptr(), result) };
        if let Err(error) = self.callback_result() {
            let _ = Error::capture();
            return Err(error.into());
        }
        self.classify_status(kind as u32, result, errno)
    }

    // SSL_get_error is called immediately after native I/O; interpretation owns
    // no native pointers and can be checked independently of TLS scheduling.
    fn classify_status(&mut self, kind: u32, result: i32, errno: Option<i32>) -> IoResult<usize> {
        match kind {
            ffi::SSL_ERROR_NONE if result > 0 => Ok(result as usize),
            ffi::SSL_ERROR_WANT_READ => Err(IoError::WantRead),
            ffi::SSL_ERROR_WANT_WRITE => Err(IoError::WantWrite),
            ffi::SSL_ERROR_WANT_X509_LOOKUP => Err(IoError::WantCertificate),
            ffi::SSL_ERROR_ZERO_RETURN => Err(IoError::Closed),
            _ => {
                let native = Error::capture();
                self.poisoned = true;
                self.pending_write = None;
                if kind == ffi::SSL_ERROR_SYSCALL {
                    Err(IoError::System {
                        code: errno.filter(|code| *code != 0),
                        native,
                    })
                } else {
                    Err(IoError::Failure(native))
                }
            }
        }
    }
    pub fn handshake(&mut self) -> IoResult<()> {
        self.ready()?;
        if self.pending_write.is_some() {
            return Err(Error::InvalidState(
                "retry the pending write before a handshake operation",
            )
            .into());
        }
        self.begin_io();
        // SAFETY: Exclusive configured connection, owned live transport, no
        // outstanding borrowed buffers; synchronous native handshake operation.
        let result = unsafe { ffi::SSL_do_handshake(self.native.0.as_ptr()) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        self.classify(result, errno).map(|_| ())
    }
    /// Retry after WantRead/WantWrite using identical bytes. This method owns
    /// and erases the pending plaintext, keeping its address and contents stable
    /// until the native write succeeds or the connection is irrecoverably failed.
    pub fn write(&mut self, bytes: &[u8]) -> IoResult<usize> {
        self.ready()?;
        let len = i32::try_from(bytes.len())
            .map_err(|_| Error::InvalidInput("TLS write exceeds INT_MAX"))?;
        if let Some(pending) = &self.pending_write {
            if pending.as_ref() != bytes {
                return Err(
                    Error::InvalidState("a TLS write retry must use identical bytes").into(),
                );
            }
        } else {
            if bytes.is_empty() {
                return Ok(0);
            }
            self.pending_write = Some(bytes.to_vec().into());
        }
        self.begin_io();
        let pending = self.pending_write.as_ref().unwrap();
        // SAFETY: Pending storage is owned, immutable, and retained across every
        // retry. It covers the checked length and cannot alias native output.
        let result = unsafe {
            ffi::SSL_write(
                self.native.0.as_ptr(),
                pending.as_ref().as_ptr().cast(),
                len,
            )
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        let outcome = self.classify(result, errno);
        self.write_wants_write = matches!(outcome, Err(IoError::WantWrite));
        if outcome.is_ok() {
            self.pending_write = None;
        }
        outcome
    }
    pub fn read(&mut self, output: &mut [u8], peek: bool) -> IoResult<usize> {
        self.ready()?;
        if self.write_wants_write {
            return Err(Error::InvalidState(
                "only the pending write may be retried after WantWrite",
            )
            .into());
        }
        let len = i32::try_from(output.len())
            .map_err(|_| Error::InvalidInput("TLS read exceeds INT_MAX"))?;
        if output.is_empty() {
            return Ok(0);
        }
        self.begin_io();
        // SAFETY: Exclusive SSL and writable output of the checked length. SSL
        // does not retain the read destination after returning, including WANT.
        let result = unsafe {
            if peek {
                ffi::SSL_peek(self.native.0.as_ptr(), output.as_mut_ptr().cast(), len)
            } else {
                ffi::SSL_read(self.native.0.as_ptr(), output.as_mut_ptr().cast(), len)
            }
        };
        let errno = std::io::Error::last_os_error().raw_os_error();
        self.classify(result, errno)
    }
    pub fn shutdown(&mut self) -> IoResult<bool> {
        self.ready()?;
        if self.pending_write.is_some() {
            return Err(Error::InvalidState("complete the pending write before shutdown").into());
        }
        self.begin_io();
        // SAFETY: The exclusive connection has not suffered a fatal error and
        // has no outstanding write. Transport and all context owners remain live.
        let result = unsafe { ffi::SSL_shutdown(self.native.0.as_ptr()) };
        let errno = std::io::Error::last_os_error().raw_os_error();
        if result == 0 {
            self.callback_result()?;
            return Ok(false);
        }
        self.classify(result, errno).map(|_| true)
    }
    pub fn feed_ciphertext(&mut self, bytes: &[u8]) -> IoResult<usize> {
        self.ready()?;
        if self.input_closed {
            return Err(Error::InvalidState("input transport has reached EOF").into());
        }
        if let Transport::Datagrams { input, .. } = &self.transport {
            return input.feed(bytes);
        }
        let Transport::Memory { input, .. } = self.transport else {
            return Err(Error::InvalidState("connection uses a socket transport").into());
        };
        let len = i32::try_from(bytes.len())
            .map_err(|_| Error::InvalidInput("TLS transport input exceeds INT_MAX"))?;
        if len == 0 {
            return Ok(0);
        }
        // SAFETY: Input is borrowed only until it is copied into the owned BIO.
        let written = unsafe { ffi::BIO_write(input.as_ptr(), bytes.as_ptr().cast(), len) };
        crate::error::check_positive(written).map_err(Into::into)
    }
    pub fn drain_ciphertext(&mut self, output: &mut [u8]) -> IoResult<usize> {
        // Draining already-produced alert bytes remains useful after failure.
        if let Transport::Datagrams { output: queue, .. } = &self.transport {
            return queue.drain(output);
        }
        let Transport::Memory { output: bio, .. } = self.transport else {
            return Err(Error::InvalidState("connection uses a socket transport").into());
        };
        let len = i32::try_from(output.len())
            .map_err(|_| Error::InvalidInput("TLS transport output exceeds INT_MAX"))?;
        if len == 0 {
            return Ok(0);
        }
        // SAFETY: The SSL-owned output BIO is exclusive and the Rust destination
        // is writable for len. The BIO retains no destination pointer.
        let read = unsafe { ffi::BIO_read(bio.as_ptr(), output.as_mut_ptr().cast(), len) };
        if read > 0 {
            return Ok(read as usize);
        }
        // SAFETY: Exclusive live BIO query; a retry means it currently has no data.
        if unsafe { ffi::OB_bio_retry(bio.as_ptr()) } != 0 {
            return Err(IoError::WantRead);
        }
        Err(Error::capture().into())
    }
    pub fn input_eof(&mut self) -> Result<()> {
        if let Transport::Datagrams { input, .. } = &self.transport {
            input.eof()?;
            self.input_closed = true;
            return Ok(());
        }
        let Transport::Memory { input, .. } = self.transport else {
            return Err(Error::InvalidState("connection uses a socket transport"));
        };
        // SAFETY: Exclusive memory BIO. Existing buffered ciphertext is still
        // consumed before subsequent reads observe the new EOF return value.
        unsafe { ffi::OB_bio_eof_return(input.as_ptr(), 0) };
        self.input_closed = true;
        Ok(())
    }
}
