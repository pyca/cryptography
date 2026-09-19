use super::*;
use std::{
    ffi::c_void,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Mutex, MutexGuard, OnceLock},
};

/// Synchronous TLS callbacks receive copied metadata and return typed actions.
/// No native pointer or mutable connection reference is exposed. Callback state
/// may be shared between connections and must synchronize its own mutation.
/// Returning an error (or panicking) permanently fails the initiating connection.
pub trait Callbacks: Send + Sync {
    /// Returning true explicitly overrides the native verification result. The
    /// default preserves native verification, including its failures.
    fn verify(
        &self,
        _info: &ConnectionInfo,
        _certificate: &[u8],
        _error: i32,
        _depth: i32,
        native_ok: bool,
    ) -> Result<bool> {
        Ok(native_ok)
    }
    /// Select a frozen server context during SNI processing. The connection's
    /// verification policy remains unchanged, as with SSL_set_SSL_CTX.
    fn server_name(&self, _info: &ConnectionInfo) -> Result<Option<Context>> {
        Ok(None)
    }
    /// None declines ALPN. Some must be one of the offered nonempty protocols.
    fn select_alpn(&self, _info: &ConnectionInfo, _offered: &[Vec<u8>]) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn info(&self, _info: &ConnectionInfo, _event: i32, _result: i32) -> Result<()> {
        Ok(())
    }
    /// Key log lines contain traffic secrets. This hook is disabled unless the
    /// builder explicitly enables it; consumers must protect any resulting log.
    fn key_log(&self, _info: &ConnectionInfo, _line: &[u8]) -> Result<()> {
        Ok(())
    }
    fn ocsp_response(&self, _info: &ConnectionInfo) -> Result<Option<Vec<u8>>> {
        Ok(None)
    }
    fn verify_ocsp(&self, _info: &ConnectionInfo, _response: &[u8]) -> Result<bool> {
        Ok(true)
    }
    fn generate_cookie(&self, _info: &ConnectionInfo) -> Result<Vec<u8>> {
        Err(Error::Unsupported("no DTLS cookie generator configured"))
    }
    fn verify_cookie(&self, _info: &ConnectionInfo, _cookie: &[u8]) -> Result<bool> {
        Ok(false)
    }
}
struct DefaultCallbacks;
impl Callbacks for DefaultCallbacks {}

// SSL_get_error examines both the thread's error queue and errno. Application
// callbacks may drain that queue or execute unrelated native operations. Keep
// the TLS operation's codes and errno isolated, including during unwinding.
// The abstraction exposes owned error codes/descriptions, not file/data fields.
struct ErrorScope {
    codes: Vec<std::os::raw::c_ulong>,
    errno: i32,
}
impl ErrorScope {
    fn enter() -> Self {
        // SAFETY: All three operations access only the current thread's state.
        unsafe {
            let errno = ffi::OB_get_errno();
            let mut codes = Vec::new();
            loop {
                let code = ffi::ERR_get_error();
                if code == 0 {
                    break;
                }
                #[allow(clippy::useless_conversion)]
                codes.push(code.into());
            }
            Self { codes, errno }
        }
    }
}
impl Drop for ErrorScope {
    fn drop(&mut self) {
        // SAFETY: Codes came from this thread's native queue; restoring them in
        // order preserves SSL_get_error classification. No borrowed data escapes.
        unsafe {
            ffi::ERR_clear_error();
            for code in &self.codes {
                ffi::OB_restore_error(*code);
            }
            ffi::OB_set_errno(self.errno);
        }
    }
}

pub(super) struct Records {
    pub context: Context,
    pub failure: Option<Error>,
    pub verification_chain: Option<Vec<Vec<u8>>>,
    pub finished: [Vec<u8>; 2],
    pub hello_randoms: [Option<[u8; 32]>; 2],
    pub client_ca_names: Vec<Vec<u8>>,
    ocsp_requested: bool,
    // Keep every ALPN selection allocation stable until SSL destruction, even
    // if a backend invokes the callback again during a subsequent handshake.
    alpn: Vec<Vec<u8>>,
}
pub(super) struct CallbackState {
    pub(super) hooks: Mutex<Arc<dyn Callbacks>>,
    pub records: Mutex<Records>,
}
pub(super) fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // Recover only our internal bookkeeping after an unwinding application hook.
    // No native owner or untrusted callback executes while these locks are held.
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
fn ex_index() -> Result<i32> {
    static INDEX: OnceLock<i32> = OnceLock::new();
    let index = *INDEX.get_or_init(|| {
        // SAFETY: Allocate one process-wide SSL ex-data slot; no free callback
        // is needed because the Rust connection retains the Arc through SSL_free.
        unsafe { ffi::OB_tls_ex_index() }
    });
    if index < 0 {
        Err(Error::InvalidState(
            "could not allocate TLS callback storage index",
        ))
    } else {
        Ok(index)
    }
}
impl CallbackState {
    pub fn new(context: Context) -> Arc<Self> {
        static DEFAULT: OnceLock<Arc<dyn Callbacks>> = OnceLock::new();
        Arc::new(Self {
            hooks: Mutex::new(DEFAULT.get_or_init(|| Arc::new(DefaultCallbacks)).clone()),
            records: Mutex::new(Records {
                context,
                failure: None,
                verification_chain: None,
                finished: [Vec::new(), Vec::new()],
                hello_randoms: [None, None],
                client_ca_names: Vec::new(),
                ocsp_requested: false,
                alpn: Vec::new(),
            }),
        })
    }
    pub(super) fn attach(self: &Arc<Self>, native: &NativeConnection) -> Result<()> {
        // SAFETY: Arc allocation never moves and remains alive until after SSL
        // destruction. The ex-data slot contains only a shared CallbackState
        // pointer, never an aliased &mut Connection or a Box's unique pointee.
        check(unsafe {
            ffi::SSL_set_ex_data(
                native.0.as_ptr(),
                ex_index()?,
                Arc::as_ptr(self).cast_mut().cast(),
            )
        })
    }
}

// SAFETY contract: SSL is a live callback argument; state remains retained by
// the enclosing connection for the entire native operation and destruction.
unsafe fn dispatch<T>(
    ssl: *mut ffi::SSL,
    operation: impl FnOnce(&CallbackState, &dyn Callbacks) -> Result<T>,
) -> Result<T> {
    let _error_scope = ErrorScope::enter();
    // SAFETY: Query this module's slot from the live SSL. NULL can occur before
    // constructor attachment; no user callback is dispatched in that case.
    let raw = unsafe { ffi::SSL_get_ex_data(ssl, ex_index()?) }.cast::<CallbackState>();
    if raw.is_null() {
        return Err(Error::InvalidState("TLS callback storage not attached"));
    }
    // SAFETY: Constructor retained the shared Arc allocation through SSL_free.
    let state = unsafe { &*raw };
    if let Some(error) = &lock(&state.records).failure {
        return Err(error.clone());
    }
    let hooks = lock(&state.hooks).clone();
    let result = catch_unwind(AssertUnwindSafe(|| operation(state, &*hooks)))
        .unwrap_or(Err(Error::InvalidState("TLS callback panicked")));
    if let Err(error) = &result {
        lock(&state.records).failure = Some(error.clone());
    }
    result
}

pub(super) unsafe extern "C" fn verify(native_ok: i32, store: *mut ffi::X509_STORE_CTX) -> i32 {
    // SAFETY: OpenSSL supplies a live store context during certificate checking.
    // SSL's dedicated store index identifies the initiating SSL. All source
    // certificates and chain are copied while this callback owns the operation.
    unsafe {
        let index = ffi::SSL_get_ex_data_X509_STORE_CTX_idx();
        let ssl = ffi::X509_STORE_CTX_get_ex_data(store, index).cast::<ffi::SSL>();
        if ssl.is_null() {
            return 0;
        }
        dispatch(ssl, |state, hooks| {
            let cert = metadata::certificate_copy(ffi::X509_STORE_CTX_get_current_cert(store))?;
            let error = ffi::X509_STORE_CTX_get_error(store);
            let depth = ffi::X509_STORE_CTX_get_error_depth(store);
            let chain = metadata::chain_copy(ffi::X509_STORE_CTX_get0_chain(store))?;
            lock(&state.records).verification_chain = Some(chain);
            let accepted = hooks.verify(
                &metadata::snapshot(ssl),
                &cert,
                error,
                depth,
                native_ok != 0,
            )?;
            if accepted {
                ffi::X509_STORE_CTX_set_error(store, ffi::X509_V_OK as i32);
            }
            Ok(i32::from(accepted))
        })
        .unwrap_or(0)
    }
}
unsafe extern "C" fn server_name(ssl: *mut ffi::SSL, _alert: *mut i32, _: *mut c_void) -> i32 {
    // SAFETY: Native SNI callback supplies the exclusively active SSL. Switching
    // context is a supported action here; the selected immutable factory remains
    // retained in callback state and SSL acquires its own native reference.
    unsafe {
        dispatch(ssl, |state, hooks| {
            if let Some(context) = hooks.server_name(&metadata::snapshot(ssl))? {
                if context.protocol() != lock(&state.records).context.protocol() {
                    return Err(Error::InvalidInput("cannot switch TLS transport protocol"));
                }
                pointer(ffi::SSL_set_SSL_CTX(ssl, context.0.native.0.as_ptr()))?;
                lock(&state.records).context = context;
            }
            Ok(ffi::SSL_TLSEXT_ERR_OK as i32)
        })
        .unwrap_or(ffi::SSL_TLSEXT_ERR_ALERT_FATAL as i32)
    }
}
unsafe extern "C" fn alpn(
    ssl: *mut ffi::SSL,
    output: *mut *const u8,
    length: *mut u8,
    input: *const u8,
    input_length: u32,
    _: *mut c_void,
) -> i32 {
    // SAFETY: Native provides a readable length-prefixed protocol offer and valid
    // output slots. Store the chosen bytes in a stable allocation until SSL_free.
    unsafe {
        dispatch(ssl, |state, hooks| {
            let mut wire = if input_length == 0 {
                &[][..]
            } else {
                std::slice::from_raw_parts(input, input_length as usize)
            };
            let mut offered = Vec::new();
            while let Some((&length, remaining)) = wire.split_first() {
                if length == 0 || remaining.len() < length as usize {
                    return Err(Error::InvalidInput("invalid peer ALPN offer"));
                }
                offered.push(remaining[..length as usize].to_vec());
                wire = &remaining[length as usize..];
            }
            let Some(chosen) = hooks.select_alpn(&metadata::snapshot(ssl), &offered)? else {
                return Ok(ffi::SSL_TLSEXT_ERR_NOACK as i32);
            };
            if !offered.contains(&chosen) {
                return Err(Error::InvalidInput(
                    "ALPN selection was not offered by the peer",
                ));
            }
            *length = chosen.len() as u8;
            *output = chosen.as_ptr();
            lock(&state.records).alpn.push(chosen);
            Ok(ffi::SSL_TLSEXT_ERR_OK as i32)
        })
        .unwrap_or(ffi::SSL_TLSEXT_ERR_ALERT_FATAL as i32)
    }
}
unsafe extern "C" fn info(ssl: *const ffi::SSL, event: i32, result: i32) {
    // SAFETY: Callback metadata queries do not mutate SSL's protocol state. The
    // native operation retains exclusive ownership while invoking this callback.
    let _ = unsafe {
        dispatch(ssl.cast_mut(), |_, hooks| {
            hooks.info(&metadata::snapshot(ssl.cast_mut()), event, result)
        })
    };
}
#[cfg(not(backend = "libressl"))]
unsafe extern "C" fn key_log(ssl: *const ffi::SSL, line: *const std::ffi::c_char) {
    // SAFETY: Native keylog callback provides a terminated line live for this
    // invocation. Borrowed bytes never escape the synchronous safe callback.
    let _ = unsafe {
        dispatch(ssl.cast_mut(), |_, hooks| {
            hooks.key_log(
                &metadata::snapshot(ssl.cast_mut()),
                CStr::from_ptr(line).to_bytes(),
            )
        })
    };
}
unsafe extern "C" fn ocsp(ssl: *mut ffi::SSL, _: *mut c_void) -> i32 {
    // SAFETY: The active SSL is exclusive; server response ownership is copied
    // into an OPENSSL_malloc allocation by the shim and transferred exactly once.
    unsafe {
        let server = ffi::OB_tls_is_server(ssl) != 0;
        dispatch(ssl, |state, hooks| {
            let info = metadata::snapshot(ssl);
            if server {
                match hooks.ocsp_response(&info)? {
                    None => Ok(ffi::SSL_TLSEXT_ERR_NOACK as i32),
                    Some(response) if response.is_empty() => Ok(ffi::SSL_TLSEXT_ERR_NOACK as i32),
                    Some(response) => {
                        check(ffi::OB_tls_set_ocsp_response(
                            ssl,
                            response.as_ptr(),
                            response.len(),
                        ))?;
                        Ok(ffi::SSL_TLSEXT_ERR_OK as i32)
                    }
                }
            } else {
                // LibreSSL calls this hook even without status_request. A
                // registered observer is not itself a request for stapling.
                if !lock(&state.records).ocsp_requested {
                    return Ok(1);
                }
                let mut response = std::ptr::null();
                let length = ffi::OB_tls_ocsp_response(ssl, &mut response);
                let response = if length == 0 {
                    &[][..]
                } else {
                    std::slice::from_raw_parts(response, length)
                };
                Ok(i32::from(hooks.verify_ocsp(&info, response)?))
            }
        })
        .unwrap_or(if server {
            ffi::SSL_TLSEXT_ERR_ALERT_FATAL as i32
        } else {
            -1
        })
    }
}
unsafe extern "C" fn cookie_generate(ssl: *mut ffi::SSL, output: *mut u8, length: *mut u32) -> i32 {
    // SAFETY: DTLS supplies a 256-byte cookie destination. Bound the application
    // result to the protocol's one-byte length before copying into that storage.
    unsafe {
        dispatch(ssl, |_, hooks| {
            let cookie = hooks.generate_cookie(&metadata::snapshot(ssl))?;
            if cookie.is_empty() || cookie.len() > 255 {
                return Err(Error::InvalidInput("DTLS cookie length must be 1..=255"));
            }
            std::ptr::copy_nonoverlapping(cookie.as_ptr(), output, cookie.len());
            *length = cookie.len() as u32;
            Ok(1)
        })
        .unwrap_or(0)
    }
}
unsafe extern "C" fn cookie_verify(ssl: *mut ffi::SSL, cookie: *const u8, length: u32) -> i32 {
    // SAFETY: The peer's cookie slice remains readable through this callback.
    unsafe {
        dispatch(ssl, |_, hooks| {
            let cookie = if length == 0 {
                &[][..]
            } else {
                std::slice::from_raw_parts(cookie, length as usize)
            };
            Ok(i32::from(
                hooks.verify_cookie(&metadata::snapshot(ssl), cookie)?,
            ))
        })
        .unwrap_or(0)
    }
}
unsafe extern "C" fn message(
    write: i32,
    version: i32,
    content_type: i32,
    bytes: *const c_void,
    length: usize,
    ssl: *mut ffi::SSL,
    _: *mut c_void,
) {
    if content_type != 22 || length < 4 {
        return;
    }
    // SAFETY: The message callback owns readable plaintext handshake bytes for
    // this invocation. Finished messages are copied, including on BoringSSL TLS
    // 1.3 where the legacy Finished getters do not retain them.
    let _ = unsafe {
        dispatch(ssl, |state, _| {
            let bytes = std::slice::from_raw_parts(bytes.cast::<u8>(), length);
            let header = if version & 0xff00 == 0xfe00 { 12 } else { 4 };
            if bytes.len() < header {
                return Err(Error::InvalidState("truncated native handshake message"));
            }
            match bytes[0] {
                1 | 2 => {
                    let random = bytes[header..]
                        .get(2..34)
                        .ok_or(Error::InvalidState("truncated native Hello message"))?;
                    // The peer random is not retained by LibreSSL's TLS 1.3
                    // legacy getters. Copy the actual Hello value on the wire.
                    lock(&state.records).hello_randoms[usize::from(bytes[0] == 2)] =
                        Some(random.try_into().unwrap());
                }
                20 => {
                    lock(&state.records).finished[usize::from(write == 0)] =
                        bytes[header..].to_vec();
                }
                _ => (),
            }
            Ok(())
        })
    };
}

#[cfg(any(backend = "boringssl", backend = "awslc"))]
unsafe extern "C" fn certificate_requested(ssl: *mut ffi::SSL, _: *mut c_void) -> i32 {
    // SAFETY: These forks permit CA-list reads only in certificate selection
    // callbacks. Copy now, without exporting an alias or querying after TLS I/O.
    unsafe {
        dispatch(ssl, |state, _| {
            if ffi::OB_tls_is_server(ssl) == 0 {
                let names = metadata::ca_names_copy(ffi::SSL_get_client_CA_list(ssl))?;
                lock(&state.records).client_ca_names = names;
            }
            Ok(1)
        })
        .unwrap_or(0)
    }
}

pub(super) fn install(native: &NativeContext, policy: PeerVerification) -> Result<()> {
    ex_index()?;
    // SAFETY: Exclusive builder. Static function pointers have C ABI and catch
    // application panics; per-connection state is attached before protocol I/O.
    unsafe {
        ffi::SSL_CTX_set_verify(native.0.as_ptr(), policy.bits(), Some(verify));
        check(ffi::OB_tls_context_sni_callback(
            native.0.as_ptr(),
            Some(server_name),
        ))?;
        check(ffi::OB_tls_context_ocsp_callback(
            native.0.as_ptr(),
            Some(ocsp),
        ))?;
        ffi::SSL_CTX_set_alpn_select_cb(native.0.as_ptr(), Some(alpn), std::ptr::null_mut());
        ffi::SSL_CTX_set_info_callback(native.0.as_ptr(), Some(info));
        ffi::SSL_CTX_set_msg_callback(native.0.as_ptr(), Some(message));
        #[cfg(any(backend = "boringssl", backend = "awslc"))]
        ffi::SSL_CTX_set_cert_cb(
            native.0.as_ptr(),
            Some(certificate_requested),
            std::ptr::null_mut(),
        );
    }
    Ok(())
}
impl ContextBuilder {
    /// Enable delivery of traffic secrets to Callbacks::key_log.
    pub fn enable_key_logging(&mut self) -> Result<()> {
        #[cfg(backend = "libressl")]
        {
            Err(Error::Unsupported(
                "LibreSSL's keylog callback is a compatibility stub",
            ))
        }
        #[cfg(not(backend = "libressl"))]
        {
            // SAFETY: Exclusive builder; installs only the static guarded callback.
            unsafe { ffi::SSL_CTX_set_keylog_callback(self.native.0.as_ptr(), Some(key_log)) };
            Ok(())
        }
    }
    pub fn enable_cookie_callbacks(&mut self) -> Result<()> {
        // SAFETY: Exclusive builder; callbacks enforce output lengths and contain
        // panics. The shim reports unsupported backends without installing them.
        if unsafe {
            ffi::OB_tls_context_cookie_callbacks(
                self.native.0.as_ptr(),
                Some(cookie_generate),
                Some(cookie_verify),
            )
        } == 1
        {
            Ok(())
        } else {
            Err(Error::Unsupported("DTLS cookie callbacks are unavailable"))
        }
    }
}
impl Connection {
    pub fn set_callbacks(&mut self, hooks: Arc<dyn Callbacks>) -> Result<()> {
        self.configuring()?;
        *lock(&self.callbacks.hooks) = hooks;
        Ok(())
    }
    pub fn set_peer_verification(&mut self, policy: PeerVerification) -> Result<()> {
        self.configuring()?;
        if policy == PeerVerification::None && self.reference_identity.is_some() {
            return Err(Error::InvalidState(
                "reference identities require peer verification",
            ));
        }
        // SAFETY: Exclusive connection before I/O. Keep the guarded verification
        // callback so both native decisions and explicit overrides are observed.
        unsafe { ffi::SSL_set_verify(self.native.0.as_ptr(), policy.bits(), Some(verify)) };
        self.verification = policy;
        Ok(())
    }
    pub fn verification(&self) -> PeerVerification {
        self.verification
    }
    pub fn set_context(&mut self, context: Context) -> Result<()> {
        self.configuring()?;
        if context.protocol() != self.context.protocol() {
            return Err(Error::InvalidInput("cannot switch TLS transport protocol"));
        }
        // SAFETY: Exclusive connection; native SSL acquires a context reference.
        // This changes credentials, not the already configured peer policy.
        pointer(unsafe {
            ffi::SSL_set_SSL_CTX(self.native.0.as_ptr(), context.0.native.0.as_ptr())
        })?;
        lock(&self.callbacks.records).context = context.clone();
        self.context = context;
        Ok(())
    }
    pub fn request_ocsp(&mut self) -> Result<()> {
        self.configuring()?;
        // SAFETY: Exclusive connection; requests stapling without retaining data.
        check(unsafe { ffi::OB_tls_request_ocsp(self.native.0.as_ptr()) })?;
        lock(&self.callbacks.records).ocsp_requested = true;
        Ok(())
    }
    pub(super) fn callback_result(&mut self) -> Result<()> {
        let records = lock(&self.callbacks.records);
        self.context = records.context.clone();
        // A context switch during SNI does not necessarily copy protocol
        // bounds. Refuse a negotiated protocol that cannot honor its CA hints.
        if cfg!(backend = "libressl")
            && !self.context.0.client_ca_names.is_empty()
            // SAFETY: The initiating operation still exclusively owns this SSL.
            && unsafe { ffi::SSL_version(self.native.0.as_ptr()) } == ffi::TLS1_3_VERSION as i32
        {
            self.poisoned = true;
            self.pending_write = None;
            return Err(Error::Unsupported(
                "LibreSSL does not send TLS 1.3 CA names",
            ));
        }
        if let Some(error) = &records.failure {
            self.poisoned = true;
            self.pending_write = None;
            Err(error.clone())
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn connection() -> Connection {
        let context = ContextBuilder::new(Protocol::Tls, PeerVerification::None)
            .unwrap()
            .finish();
        Connection::memory(context, super::super::Role::Server).unwrap()
    }

    #[test]
    fn unattached_native_objects_do_not_dispatch_user_callbacks() {
        let context = ContextBuilder::new(Protocol::Tls, PeerVerification::None)
            .unwrap()
            .finish();
        let native = Connection::allocate(&context, super::super::Role::Server).unwrap();
        // SAFETY: The SSL is live but has not yet had callback state attached.
        assert!(unsafe { dispatch(native.0.as_ptr(), |_, _| Ok(())) }.is_err());
        // SAFETY: A newly allocated store context has no initiating SSL. The
        // callback rejects it before accessing a current certificate or chain.
        unsafe {
            let store = pointer(ffi::X509_STORE_CTX_new()).unwrap();
            assert_eq!(verify(1, store.as_ptr()), 0);
            ffi::X509_STORE_CTX_free(store.as_ptr());
        }
    }

    #[test]
    fn malformed_alpn_and_handshake_records_fail_closed() {
        for offered in [&[][..], &[0], &[3, b'h']] {
            let mut connection = connection();
            let mut output = std::ptr::null();
            let mut length = 0;
            // SAFETY: SSL and all explicit input/output slots are live. This
            // tests bounded malformed wire data without forging any pointers.
            let result = unsafe {
                alpn(
                    connection.native.0.as_ptr(),
                    &mut output,
                    &mut length,
                    offered.as_ptr(),
                    offered.len() as u32,
                    std::ptr::null_mut(),
                )
            };
            assert_eq!(
                result,
                if offered.is_empty() {
                    ffi::SSL_TLSEXT_ERR_NOACK as i32
                } else {
                    ffi::SSL_TLSEXT_ERR_ALERT_FATAL as i32
                }
            );
            assert!(output.is_null());
            assert_eq!(length, 0);
            assert_eq!(connection.callback_result().is_ok(), offered.is_empty());
        }
        let mut connection = connection();
        let truncated = [1u8, 0, 0, 0];
        // SAFETY: The advertised four bytes exist, but do not contain the
        // twelve-byte DTLS handshake header, so no native parsing is attempted.
        unsafe {
            message(
                0,
                ffi::DTLS1_2_VERSION as i32,
                22,
                truncated.as_ptr().cast(),
                truncated.len(),
                connection.native.0.as_ptr(),
                std::ptr::null_mut(),
            )
        };
        assert!(connection.callback_result().is_err());
        assert!(connection.handshake().is_err());
    }

    struct Cookie(Vec<u8>);
    impl Callbacks for Cookie {
        fn generate_cookie(&self, _: &super::metadata::ConnectionInfo) -> Result<Vec<u8>> {
            Ok(self.0.clone())
        }
        fn verify_cookie(
            &self,
            _: &super::metadata::ConnectionInfo,
            cookie: &[u8],
        ) -> Result<bool> {
            Ok(cookie == self.0)
        }
    }

    #[test]
    fn callback_cookie_bounds_protect_native_output() {
        for cookie in [vec![], vec![1; 256]] {
            let mut connection = connection();
            connection.set_callbacks(Arc::new(Cookie(cookie))).unwrap();
            let mut output = [0xa5; 256];
            let mut length = 0;
            // SAFETY: The output has the callback contract's full capacity.
            assert_eq!(
                unsafe {
                    cookie_generate(
                        connection.native.0.as_ptr(),
                        output.as_mut_ptr(),
                        &mut length,
                    )
                },
                0
            );
            assert_eq!(length, 0);
            assert_eq!(output, [0xa5; 256]);
            assert!(connection.callback_result().is_err());
        }
        let mut connection = connection();
        connection.set_callbacks(Arc::new(Cookie(vec![]))).unwrap();
        // SAFETY: An empty cookie requires no input access.
        assert_eq!(
            unsafe { cookie_verify(connection.native.0.as_ptr(), std::ptr::null(), 0) },
            1
        );
    }
}
