// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository.
//! Typed pyOpenSSL TLS adapters. No native pointer crosses this module.
#![forbid(unsafe_code)]
use super::bridge_error;
use openssl_bridge::{tls, x509, Error};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyModule};
use std::{
    cell::RefCell,
    sync::{Arc, Mutex, MutexGuard},
};

pyo3::create_exception!(pyopenssl, TLSWantRead, pyo3::exceptions::PyException);
pyo3::create_exception!(pyopenssl, TLSWantWrite, pyo3::exceptions::PyException);
pyo3::create_exception!(pyopenssl, TLSWantCertificate, pyo3::exceptions::PyException);
pyo3::create_exception!(pyopenssl, TLSClosed, pyo3::exceptions::PyException);
pyo3::create_exception!(pyopenssl, TLSSystemError, pyo3::exceptions::PyException);

#[cfg(test)]
mod tests {
    use super::*;
    use tls::Callbacks;

    #[test]
    fn callback_exceptions_preserve_the_first_error_and_context_switches_are_owned() {
        Python::initialize();
        Python::attach(|py| {
            let context = tls::ContextBuilder::new(tls::Protocol::Tls, tls::PeerVerification::None)
                .unwrap()
                .finish();
            let info = tls::Connection::memory(context, tls::Role::Client)
                .unwrap()
                .info();
            let module = PyModule::from_code(py, c"class Owner:\n    def _dispatch_native_callback(self, event, info, args):\n        raise RuntimeError(event)\n", c"callbacks.py", c"callbacks").unwrap();
            let owner = module.getattr("Owner").unwrap().call0().unwrap().unbind();
            let active = ActiveGuard::new(owner);
            let hooks = PythonCallbacks;
            assert!(hooks.verify(&info, b"certificate", 1, 0, false).is_err());
            assert!(hooks.server_name(&info).is_err());
            assert!(hooks.select_alpn(&info, &[b"h2".to_vec()]).is_err());
            assert!(hooks.info(&info, 1, 1).is_err());
            assert!(hooks.key_log(&info, b"secret").is_err());
            assert!(hooks.ocsp_response(&info).is_err());
            assert!(hooks.verify_ocsp(&info, b"response").is_err());
            assert!(hooks.generate_cookie(&info).is_err());
            assert!(hooks.verify_cookie(&info, b"cookie").is_err());
            let error = active.error().unwrap();
            assert!(error.is_instance_of::<pyo3::exceptions::PyRuntimeError>(py));
            assert_eq!(error.value(py).str().unwrap().to_str().unwrap(), "verify");
            drop(active);
            assert!(hooks.info(&info, 1, 1).is_err());

            let module = PyModule::from_code(py, c"class Owner:\n    def _dispatch_native_callback(self, event, info, args):\n        return replacement\n", c"callbacks.py", c"callbacks").unwrap();
            let replacement = PyContext::new(false).unwrap();
            replacement.set_verify(1).unwrap();
            module
                .add("replacement", Py::new(py, replacement).unwrap())
                .unwrap();
            let active =
                ActiveGuard::new(module.getattr("Owner").unwrap().call0().unwrap().unbind());
            let replacement = hooks.server_name(&info).unwrap().unwrap();
            assert_eq!(replacement.protocol(), tls::Protocol::Tls);
            assert!(matches!(
                replacement.verification(),
                tls::PeerVerification::Chain { .. }
            ));
            assert!(active.error().is_none());
        });
    }

    #[test]
    fn io_errors_preserve_retry_close_errno_and_native_diagnostics() {
        Python::initialize();
        Python::attach(|py| {
            assert!(io_error(tls::IoError::WantRead).is_instance_of::<TLSWantRead>(py));
            assert!(io_error(tls::IoError::WantWrite).is_instance_of::<TLSWantWrite>(py));
            assert!(
                io_error(tls::IoError::WantCertificate).is_instance_of::<TLSWantCertificate>(py)
            );
            assert!(io_error(tls::IoError::Closed).is_instance_of::<TLSClosed>(py));
            for code in [None, Some(5)] {
                let error = io_error(tls::IoError::System {
                    code,
                    native: Error::Native(vec![]),
                });
                assert!(error.is_instance_of::<TLSSystemError>(py));
                let (number, message): (i32, String) =
                    error.value(py).getattr("args").unwrap().extract().unwrap();
                assert_eq!(number, code.unwrap_or(-1));
                assert!(!message.is_empty());
            }
            for reason in [
                "unexpected eof while reading",
                "UNEXPECTED_EOF_WHILE_READING",
                "bad record",
            ] {
                let native = Error::Native(vec![openssl_bridge::error::NativeError {
                    code: 1,
                    library: 1,
                    reason: 1,
                    description: "error:1:SSL:bad record".into(),
                    reason_text: reason.into(),
                }]);
                assert!(io_error(tls::IoError::System {
                    code: None,
                    native: native.clone()
                })
                .is_instance_of::<super::super::NativeError>(py));
                let error = io_error(tls::IoError::Failure(native));
                if reason == "bad record" {
                    assert!(error.is_instance_of::<super::super::NativeError>(py));
                } else {
                    assert!(error.is_instance_of::<TLSSystemError>(py));
                }
            }
            assert!(
                io_error(tls::IoError::Failure(Error::InvalidState("state")))
                    .is_instance_of::<pyo3::exceptions::PyValueError>(py)
            );
        });
    }
}

fn exclusive<T>(mutex: &Mutex<T>) -> PyResult<MutexGuard<'_, T>> {
    mutex.try_lock().map_err(|_| {
        pyo3::exceptions::PyRuntimeError::new_err("concurrent or reentrant TLS operation")
    })
}
fn policy(mode: u32) -> PyResult<tls::PeerVerification> {
    if mode & !7 != 0 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "unsupported peer verification flags",
        ));
    }
    Ok(if mode & 1 == 0 {
        tls::PeerVerification::None
    } else {
        tls::PeerVerification::Chain {
            require_certificate: mode & 2 != 0,
            once: mode & 4 != 0,
        }
    })
}
fn mode(policy: tls::PeerVerification) -> u32 {
    match policy {
        tls::PeerVerification::None => 0,
        tls::PeerVerification::Chain {
            require_certificate,
            once,
        } => 1 | if require_certificate { 2 } else { 0 } | if once { 4 } else { 0 },
    }
}
fn role(server: bool) -> tls::Role {
    if server {
        tls::Role::Server
    } else {
        tls::Role::Client
    }
}
fn io_error(error: tls::IoError) -> PyErr {
    match error {
        tls::IoError::WantRead => TLSWantRead::new_err(()),
        tls::IoError::WantWrite => TLSWantWrite::new_err(()),
        tls::IoError::WantCertificate => TLSWantCertificate::new_err(()),
        tls::IoError::Closed => TLSClosed::new_err(()),
        tls::IoError::System { code, native } => {
            if code.is_some() || matches!(&native, Error::Native(errors) if errors.is_empty()) {
                TLSSystemError::new_err((
                    code.unwrap_or(-1),
                    code.map_or_else(
                        || "Unexpected EOF".into(),
                        |code| std::io::Error::from_raw_os_error(code).to_string(),
                    ),
                ))
            } else {
                bridge_error(native)
            }
        }
        tls::IoError::Failure(Error::Native(ref errors))
            if errors.iter().any(|e| {
                e.reason_text
                    .replace('_', " ")
                    .eq_ignore_ascii_case("unexpected eof while reading")
            }) =>
        {
            TLSSystemError::new_err((-1, "Unexpected EOF"))
        }
        tls::IoError::Failure(error) => bridge_error(error),
    }
}
struct Config {
    builder: Option<tls::ContextBuilder>,
    frozen: Option<tls::Context>,
    verify_depth: i32,
    cache_mode: i64,
    timeout: i64,
}
// NO-COVERAGE-START
// PyO3 generates fallible type-registration machinery for this declaration.
#[pyclass(
    module = "cryptography.hazmat.bindings._rust.pyopenssl",
    name = "TLSContext"
)]
// NO-COVERAGE-END
pub(super) struct PyContext {
    config: Mutex<Config>,
    hooks: Arc<PythonCallbacks>,
}
impl PyContext {
    fn configure<T>(
        &self,
        operation: impl FnOnce(&mut tls::ContextBuilder) -> openssl_bridge::Result<T>,
    ) -> PyResult<T> {
        let mut config = exclusive(&self.config)?;
        let builder = config.builder.as_mut().ok_or_else(|| {
            pyo3::exceptions::PyValueError::new_err(
                "Context has already been used to create a Connection, it cannot be mutated again",
            )
        })?;
        let result = operation(builder).map_err(bridge_error)?;
        let metadata = (
            builder.verify_depth(),
            builder.session_cache_mode(),
            builder.session_timeout(),
        );
        config.verify_depth = metadata.0;
        config.cache_mode = metadata.1;
        config.timeout = metadata.2;
        Ok(result)
    }
    fn freeze(&self) -> PyResult<tls::Context> {
        let mut config = exclusive(&self.config)?;
        if let Some(builder) = config.builder.take() {
            config.frozen = Some(builder.finish());
        }
        Ok(config.frozen.as_ref().unwrap().clone())
    }
}
#[pymethods]
impl PyContext {
    #[new]
    fn new(datagram: bool) -> PyResult<Self> {
        let mut builder = tls::ContextBuilder::new(
            if datagram {
                tls::Protocol::Dtls
            } else {
                tls::Protocol::Tls
            },
            tls::PeerVerification::None,
        )
        .map_err(bridge_error)?;
        let (verify_depth, cache_mode, timeout) = (
            builder.verify_depth(),
            builder.session_cache_mode(),
            builder.session_timeout(),
        );
        Ok(Self {
            config: Mutex::new(Config {
                builder: Some(builder),
                frozen: None,
                verify_depth,
                cache_mode,
                timeout,
            }),
            hooks: Arc::new(PythonCallbacks),
        })
    }
    fn verify<'p>(
        &self,
        py: Python<'p>,
        leaf: &[u8],
        chain: Vec<Vec<u8>>,
    ) -> PyResult<Vec<Bound<'p, PyBytes>>> {
        let mut config = exclusive(&self.config)?;
        let result = if let Some(builder) = &mut config.builder {
            builder.verify_certificate(leaf, &chain)
        } else {
            config
                .frozen
                .as_ref()
                .unwrap()
                .verify_certificate(leaf, &chain)
        };
        match result {
            Ok(chain) => Ok(chain.iter().map(|der| PyBytes::new(py, der)).collect()),
            Err(x509::VerificationError::Backend(error)) => Err(bridge_error(error)),
            Err(x509::VerificationError::Untrusted(error)) => {
                Err(super::VerificationError::new_err((
                    error.code,
                    error.depth,
                    error.message,
                    error
                        .certificate_der
                        .map(|der| PyBytes::new(py, &der).unbind()),
                )))
            }
        }
    }
    fn set_verify(&self, flags: u32) -> PyResult<()> {
        let policy = policy(flags)?;
        self.configure(|b| {
            b.set_peer_verification(policy);
            Ok(())
        })
    }
    fn get_verify_mode(&self) -> PyResult<u32> {
        let c = exclusive(&self.config)?;
        Ok(mode(c.builder.as_ref().map_or_else(
            || c.frozen.as_ref().unwrap().verification(),
            |b| b.verification(),
        )))
    }
    fn get_verify_depth(&self) -> PyResult<i32> {
        Ok(exclusive(&self.config)?.verify_depth)
    }
    fn set_verify_depth(&self, depth: u32) -> PyResult<()> {
        self.configure(|b| b.set_verify_depth(depth))
    }
    fn get_session_cache_mode(&self) -> PyResult<i64> {
        Ok(exclusive(&self.config)?.cache_mode)
    }
    fn set_session_cache_mode(&self, value: i64) -> PyResult<i64> {
        self.configure(|b| b.set_session_cache_mode(value))
    }
    fn get_timeout(&self) -> PyResult<i64> {
        Ok(exclusive(&self.config)?.timeout)
    }
    fn set_timeout(&self, value: u32) -> PyResult<()> {
        self.configure(|b| b.set_session_timeout(value))
    }
    fn set_client_ca_names(&self, names: Vec<Vec<u8>>) -> PyResult<()> {
        self.configure(|b| b.set_client_ca_names(&names))
    }
    fn set_alpn_protocols(&self, protocols: Vec<Vec<u8>>) -> PyResult<()> {
        self.configure(|b| {
            b.set_alpn_protocols(&protocols.iter().map(Vec::as_slice).collect::<Vec<_>>())
        })
    }
    #[pyo3(signature=(file=None,directory=None))]
    fn load_verify_locations(&self, file: Option<&[u8]>, directory: Option<&[u8]>) -> PyResult<()> {
        let file = file.map(x509::c_string).transpose().map_err(bridge_error)?;
        let directory = directory
            .map(x509::c_string)
            .transpose()
            .map_err(bridge_error)?;
        self.configure(|b| b.load_verify_locations(file.as_deref(), directory.as_deref()))
    }
    fn set_min_version(&self, version: i32) -> PyResult<()> {
        self.configure(|b| b.set_min_version(version))
    }
    fn set_max_version(&self, version: i32) -> PyResult<()> {
        self.configure(|b| b.set_max_version(version))
    }
    fn set_options(&self, value: u64) -> PyResult<u64> {
        self.configure(|b| Ok(b.set_options(value)))
    }
    fn set_modes(&self, value: u64) -> PyResult<u64> {
        self.configure(|b| b.set_modes(value))
    }
    fn clear_modes(&self, value: u64) -> PyResult<u64> {
        self.configure(|b| b.clear_modes(value))
    }
    fn use_certificate_der(&self, der: &[u8]) -> PyResult<()> {
        self.configure(|b| b.use_certificate_der(der))
    }
    fn use_private_key_der(&self, der: &[u8]) -> PyResult<()> {
        self.configure(|b| b.use_private_key_der(der))
    }
    fn add_chain_certificate_der(&self, der: &[u8]) -> PyResult<()> {
        self.configure(|b| b.add_chain_certificate_der(der))
    }
    fn check_private_key(&self) -> PyResult<()> {
        self.configure(|b| b.check_private_key())
    }
    fn add_trusted_certificate_der(&self, der: &[u8]) -> PyResult<()> {
        self.configure(|b| b.add_trusted_certificate_der(der))
    }
    fn add_crl_der(&self, der: &[u8]) -> PyResult<()> {
        self.configure(|b| b.add_crl_der(der))
    }
    fn set_verification_flags(&self, value: u64) -> PyResult<()> {
        self.configure(|b| b.set_verification_flags(value))
    }
    fn set_verification_time(&self, value: i64) -> PyResult<()> {
        self.configure(|b| b.set_verification_time(value))
    }
    fn set_default_verify_paths(&self) -> PyResult<()> {
        self.configure(|b| b.set_default_verify_paths())
    }
    fn set_session_id_context(&self, value: &[u8]) -> PyResult<()> {
        self.configure(|b| b.set_session_id_context(value))
    }
    fn add_client_ca_certificate(&self, der: &[u8]) -> PyResult<()> {
        self.configure(|b| b.add_client_ca_certificate(der))
    }
    fn use_dh_parameters_pem(&self, pem: &[u8]) -> PyResult<()> {
        self.configure(|b| b.use_dh_parameters_pem(pem))
    }
    fn enable_key_logging(&self) -> PyResult<()> {
        self.configure(|b| b.enable_key_logging())
    }
    fn enable_cookie_callbacks(&self) -> PyResult<()> {
        self.configure(|b| b.enable_cookie_callbacks())
    }
    fn set_cipher_list(&self, value: &[u8]) -> PyResult<()> {
        let value = x509::c_string(value).map_err(bridge_error)?;
        self.configure(|b| b.set_cipher_list(&value))
    }
    fn set_tls13_ciphersuites(&self, value: &[u8]) -> PyResult<()> {
        let value = x509::c_string(value).map_err(bridge_error)?;
        self.configure(|b| b.set_tls13_ciphersuites(&value))
    }
    fn set_groups(&self, value: &[u8]) -> PyResult<()> {
        let value = x509::c_string(value).map_err(bridge_error)?;
        self.configure(|b| b.set_groups(&value))
    }
    fn set_srtp_profiles(&self, value: &[u8]) -> PyResult<()> {
        let value = x509::c_string(value).map_err(bridge_error)?;
        self.configure(|b| b.set_srtp_profiles(&value))
    }
}

struct ActiveOperation {
    owner: Py<PyAny>,
    error: Option<PyErr>,
}
thread_local! { static ACTIVE: RefCell<Vec<ActiveOperation>> = const { RefCell::new(Vec::new()) }; }
struct ActiveGuard;
impl ActiveGuard {
    fn new(owner: Py<PyAny>) -> Self {
        ACTIVE.with(|stack| {
            stack
                .borrow_mut()
                .push(ActiveOperation { owner, error: None })
        });
        Self
    }
    fn error(&self) -> Option<PyErr> {
        ACTIVE.with(|stack| stack.borrow_mut().last_mut().and_then(|op| op.error.take()))
    }
}
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE.with(|stack| {
            stack.borrow_mut().pop();
        });
    }
}

fn info_dict<'p>(py: Python<'p>, info: &tls::ConnectionInfo) -> PyResult<Bound<'p, PyDict>> {
    let d = PyDict::new(py);
    d.set_item(
        "servername",
        info.server_name.as_ref().map(|s| PyBytes::new(py, s)),
    )?;
    d.set_item("state", PyBytes::new(py, &info.state))?;
    d.set_item("version", info.version)?;
    d.set_item("version_name", &info.version_name)?;
    d.set_item("cipher_name", info.cipher.as_ref().map(|c| &c.name))?;
    d.set_item("cipher_bits", info.cipher.as_ref().map(|c| c.secret_bits))?;
    d.set_item("cipher_version", info.cipher.as_ref().map(|c| &c.protocol))?;
    d.set_item("alpn", PyBytes::new(py, &info.alpn))?;
    d.set_item(
        "srtp",
        PyBytes::new(py, info.srtp.as_deref().unwrap_or_default()),
    )?;
    d.set_item("group", &info.group)?;
    d.set_item("want_read", info.want_read)?;
    d.set_item("want_write", info.want_write)?;
    Ok(d)
}
fn dispatch<T>(
    info: &tls::ConnectionInfo,
    call: impl for<'p> FnOnce(Python<'p>, &Bound<'p, PyAny>, Bound<'p, PyDict>) -> PyResult<T>,
) -> openssl_bridge::Result<T> {
    Python::attach(|py| {
        // Release RefCell and native bookkeeping locks before calling Python.
        // Nested I/O on a different connection pushes its own operation frame.
        let owner = ACTIVE
            .with(|stack| stack.borrow().last().map(|op| op.owner.clone_ref(py)))
            .ok_or(Error::InvalidState(
                "TLS callback has no active Python operation",
            ))?;
        let result = info_dict(py, info).and_then(|info| call(py, owner.bind(py), info));
        result.map_err(|error| {
            ACTIVE.with(|stack| {
                // The ActiveGuard which supplied owner above remains alive
                // throughout this call, including nested Python operations.
                let mut stack = stack.borrow_mut();
                let op = stack.last_mut().unwrap();
                if op.error.is_none() {
                    op.error = Some(error);
                }
            });
            Error::InvalidState("Python TLS callback failed")
        })
    })
}
// No persistent Python reference lives in this Arc: Python owns its callbacks
// and connections through normal GC-visible references. The transient operation
// frame owns the callback target only for the duration of a native call.
struct PythonCallbacks;
impl tls::Callbacks for PythonCallbacks {
    fn verify(
        &self,
        info: &tls::ConnectionInfo,
        certificate: &[u8],
        error: i32,
        depth: i32,
        ok: bool,
    ) -> openssl_bridge::Result<bool> {
        dispatch(info, |py, owner, info| {
            owner
                .call_method1(
                    "_dispatch_native_callback",
                    (
                        "verify",
                        info,
                        (PyBytes::new(py, certificate), error, depth, ok),
                    ),
                )?
                .is_truthy()
        })
    }
    fn server_name(
        &self,
        info: &tls::ConnectionInfo,
    ) -> openssl_bridge::Result<Option<tls::Context>> {
        dispatch(info, |_, owner, info| {
            let result =
                owner.call_method1("_dispatch_native_callback", ("server_name", info, ()))?;
            if result.is_none() {
                Ok(None)
            } else {
                Ok(Some(result.extract::<PyRef<'_, PyContext>>()?.freeze()?))
            }
        })
    }
    fn select_alpn(
        &self,
        info: &tls::ConnectionInfo,
        offered: &[Vec<u8>],
    ) -> openssl_bridge::Result<Option<Vec<u8>>> {
        dispatch(info, |py, owner, info| {
            owner
                .call_method1(
                    "_dispatch_native_callback",
                    (
                        "alpn",
                        info,
                        (offered
                            .iter()
                            .map(|s| PyBytes::new(py, s))
                            .collect::<Vec<_>>(),),
                    ),
                )?
                .extract()
        })
    }
    fn info(
        &self,
        info: &tls::ConnectionInfo,
        event: i32,
        result: i32,
    ) -> openssl_bridge::Result<()> {
        dispatch(info, |_, owner, info| {
            owner.call_method1("_dispatch_native_callback", ("info", info, (event, result)))?;
            Ok(())
        })
    }
    fn key_log(&self, info: &tls::ConnectionInfo, line: &[u8]) -> openssl_bridge::Result<()> {
        dispatch(info, |py, owner, info| {
            owner.call_method1(
                "_dispatch_native_callback",
                ("keylog", info, (PyBytes::new(py, line),)),
            )?;
            Ok(())
        })
    }
    fn ocsp_response(&self, info: &tls::ConnectionInfo) -> openssl_bridge::Result<Option<Vec<u8>>> {
        dispatch(info, |_, owner, info| {
            owner
                .call_method1("_dispatch_native_callback", ("ocsp_server", info, ()))?
                .extract()
        })
    }
    fn verify_ocsp(
        &self,
        info: &tls::ConnectionInfo,
        response: &[u8],
    ) -> openssl_bridge::Result<bool> {
        dispatch(info, |py, owner, info| {
            owner
                .call_method1(
                    "_dispatch_native_callback",
                    ("ocsp_client", info, (PyBytes::new(py, response),)),
                )?
                .is_truthy()
        })
    }
    fn generate_cookie(&self, info: &tls::ConnectionInfo) -> openssl_bridge::Result<Vec<u8>> {
        dispatch(info, |_, owner, info| {
            owner
                .call_method1("_dispatch_native_callback", ("cookie_generate", info, ()))?
                .extract()
        })
    }
    fn verify_cookie(
        &self,
        info: &tls::ConnectionInfo,
        cookie: &[u8],
    ) -> openssl_bridge::Result<bool> {
        dispatch(info, |py, owner, info| {
            owner
                .call_method1(
                    "_dispatch_native_callback",
                    ("cookie_verify", info, (PyBytes::new(py, cookie),)),
                )?
                .is_truthy()
        })
    }
}

// NO-COVERAGE-START
// PyO3 generates fallible type-registration machinery for this declaration.
#[pyclass(
    module = "cryptography.hazmat.bindings._rust.pyopenssl",
    name = "TLSSession"
)]
// NO-COVERAGE-END
struct PySession {
    inner: Mutex<tls::Session>,
}
// NO-COVERAGE-START
// PyO3 generates fallible type-registration machinery for this declaration.
#[pyclass(
    module = "cryptography.hazmat.bindings._rust.pyopenssl",
    name = "TLSConnection"
)]
// NO-COVERAGE-END
struct PyConnection {
    inner: Mutex<tls::Connection>,
}
impl PyConnection {
    fn io<T: Send>(
        &self,
        owner: Py<PyAny>,
        operation: impl FnOnce(&mut tls::Connection) -> tls::IoResult<T> + Send,
    ) -> PyResult<T> {
        Python::attach(|py| {
            py.detach(move || {
                // Acquire inside detach: no MutexGuard crosses the GIL boundary.
                // Blocking socket operations allow the peer's Python thread to run.
                let mut connection = exclusive(&self.inner)?;
                let active = ActiveGuard::new(owner);
                let result = operation(&mut connection);
                if let Some(error) = active.error() {
                    return Err(error);
                }
                result.map_err(io_error)
            })
        })
    }
    fn access<T>(
        &self,
        operation: impl FnOnce(&mut tls::Connection) -> openssl_bridge::Result<T>,
    ) -> PyResult<T> {
        operation(&mut *exclusive(&self.inner)?).map_err(bridge_error)
    }
}
#[pymethods]
impl PyConnection {
    #[new]
    #[pyo3(signature=(context,server,descriptor=None))]
    fn new(context: &PyContext, server: bool, descriptor: Option<i32>) -> PyResult<Self> {
        let factory = context.freeze()?;
        let mut connection = match descriptor {
            #[cfg(unix)]
            Some(fd) => {
                tls::Connection::socket(factory, role(server), tls::SocketTransport::duplicate(fd)?)
            }
            #[cfg(not(unix))]
            Some(_) => {
                return Err(pyo3::exceptions::PyNotImplementedError::new_err(
                    "socket descriptors are only supported on Unix; use memory BIOs",
                ));
            }
            None if factory.protocol() == tls::Protocol::Dtls => {
                tls::Connection::datagrams(factory, role(server), 1500)
            }
            None => tls::Connection::memory(factory, role(server)),
        }
        .map_err(bridge_error)?;
        connection
            .set_callbacks(context.hooks.clone())
            .map_err(bridge_error)?;
        Ok(Self {
            inner: Mutex::new(connection),
        })
    }
    fn info<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyDict>> {
        info_dict(py, &exclusive(&self.inner)?.info())
    }
    fn handshake(&self, owner: Py<PyAny>) -> PyResult<()> {
        self.io(owner, |c| c.handshake())
    }
    fn shutdown(&self, owner: Py<PyAny>) -> PyResult<bool> {
        self.io(owner, |c| c.shutdown())
    }
    fn write(&self, owner: Py<PyAny>, data: crate::buf::CffiBuf<'_>) -> PyResult<usize> {
        self.io(owner, |c| c.write(data.as_bytes()))
    }
    fn read<'p>(
        &self,
        py: Python<'p>,
        owner: Py<PyAny>,
        length: usize,
        peek: bool,
    ) -> PyResult<Bound<'p, PyBytes>> {
        if length > i32::MAX as usize {
            return Err(pyo3::exceptions::PyOverflowError::new_err(
                "TLS read exceeds INT_MAX",
            ));
        }
        let mut buffer = openssl_bridge::secret::SecretBytes::from(vec![0; length]);
        let read = self.io(owner, |c| c.read(buffer.as_mut(), peek))?;
        Ok(PyBytes::new(py, &buffer.as_ref()[..read]))
    }
    fn feed_ciphertext(&self, data: crate::buf::CffiBuf<'_>) -> PyResult<usize> {
        exclusive(&self.inner)?
            .feed_ciphertext(data.as_bytes())
            .map_err(io_error)
    }
    fn drain_ciphertext<'p>(&self, py: Python<'p>, length: usize) -> PyResult<Bound<'p, PyBytes>> {
        if length > i32::MAX as usize {
            return Err(pyo3::exceptions::PyOverflowError::new_err(
                "TLS transport read exceeds INT_MAX",
            ));
        }
        let mut buffer = vec![0; length];
        let read = exclusive(&self.inner)?
            .drain_ciphertext(&mut buffer)
            .map_err(io_error)?;
        Ok(PyBytes::new(py, &buffer[..read]))
    }
    fn dtls_listen(&self, owner: Py<PyAny>) -> PyResult<()> {
        self.io(owner, |c| c.dtls_listen())
    }
    fn dtls_handle_timeout(&self, owner: Py<PyAny>) -> PyResult<bool> {
        self.io(owner, |c| c.dtls_handle_timeout())
    }
    fn dtls_timeout(&self) -> PyResult<Option<f64>> {
        self.access(|c| c.dtls_timeout().map(|t| t.map(|t| t.as_secs_f64())))
    }
    fn session(&self) -> PyResult<Option<PySession>> {
        Ok(exclusive(&self.inner)?.session().map(|inner| PySession {
            inner: Mutex::new(inner),
        }))
    }
    fn set_session(&self, session: &PySession) -> PyResult<()> {
        self.access(|c| {
            c.set_session(
                &mut *exclusive(&session.inner)
                    .map_err(|_| Error::InvalidState("session is already in use"))?,
            )
        })
    }
    fn set_role(&self, server: bool) -> PyResult<()> {
        self.access(|c| c.set_role(role(server)))
    }
    fn set_context(&self, context: &PyContext) -> PyResult<()> {
        let context = context.freeze()?;
        self.access(|c| c.set_context(context))
    }
    fn set_verify(&self, flags: u32) -> PyResult<()> {
        let policy = policy(flags)?;
        self.access(|c| c.set_peer_verification(policy))
    }
    fn get_verify_mode(&self) -> PyResult<u32> {
        Ok(mode(exclusive(&self.inner)?.verification()))
    }
    fn shutdown_state(&self) -> PyResult<u32> {
        Ok(match exclusive(&self.inner)?.shutdown_state() {
            tls::ShutdownState::Open => 0,
            tls::ShutdownState::Sent => 1,
            tls::ShutdownState::Received => 2,
            tls::ShutdownState::Both => 3,
        })
    }
    fn set_shutdown_state(&self, state: u32) -> PyResult<()> {
        let state = match state {
            0 => tls::ShutdownState::Open,
            1 => tls::ShutdownState::Sent,
            2 => tls::ShutdownState::Received,
            3 => tls::ShutdownState::Both,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "invalid shutdown state",
                ))
            }
        };
        self.access(|c| c.set_shutdown_state(state))
    }
    fn new_callback_identity(&self) -> PyResult<()> {
        self.access(|c| c.set_callbacks(Arc::new(PythonCallbacks)))
    }
    fn set_alpn_protocols(&self, protocols: Vec<Vec<u8>>) -> PyResult<()> {
        self.access(|c| {
            c.set_alpn_protocols(&protocols.iter().map(Vec::as_slice).collect::<Vec<_>>())
        })
    }
    fn random<'p>(&self, py: Python<'p>, server: bool) -> PyResult<Option<Bound<'p, PyBytes>>> {
        let mut c = exclusive(&self.inner)?;
        Ok(if server {
            c.server_random()
        } else {
            c.client_random()
        }
        .map(|bytes| PyBytes::new(py, &bytes)))
    }
    fn master_secret<'p>(&self, py: Python<'p>) -> PyResult<Option<Bound<'p, PyBytes>>> {
        Ok(self
            .access(|c| c.master_secret())?
            .map(|bytes| PyBytes::new(py, bytes.as_ref())))
    }
    fn finished<'p>(&self, py: Python<'p>, peer: bool) -> PyResult<Bound<'p, PyBytes>> {
        Ok(PyBytes::new(
            py,
            &exclusive(&self.inner)?.finished_message(peer),
        ))
    }
    #[pyo3(signature=(label,length,context=None))]
    fn exporter<'p>(
        &self,
        py: Python<'p>,
        label: &[u8],
        length: usize,
        context: Option<&[u8]>,
    ) -> PyResult<Bound<'p, PyBytes>> {
        Ok(PyBytes::new(
            py,
            self.access(|c| c.export_keying_material(label, context, length))?
                .as_ref(),
        ))
    }
    fn certificate<'p>(&self, py: Python<'p>, peer: bool) -> PyResult<Option<Bound<'p, PyBytes>>> {
        Ok(self
            .access(|c| {
                if peer {
                    c.peer_certificate_der()
                } else {
                    c.certificate_der()
                }
            })?
            .map(|d| PyBytes::new(py, &d)))
    }
    fn chain<'p>(
        &self,
        py: Python<'p>,
        verified: bool,
    ) -> PyResult<Option<Vec<Bound<'p, PyBytes>>>> {
        Ok(self
            .access(|c| {
                if verified {
                    c.verification_chain_der()
                } else {
                    c.peer_chain_der()
                }
            })?
            .map(|chain| chain.iter().map(|d| PyBytes::new(py, d)).collect()))
    }
    fn client_ca_names<'p>(&self, py: Python<'p>) -> PyResult<Vec<Bound<'p, PyBytes>>> {
        Ok(self
            .access(|c| c.client_ca_names_der())?
            .iter()
            .map(|d| PyBytes::new(py, d))
            .collect())
    }
    fn input_eof(&self) -> PyResult<()> {
        self.access(|c| c.input_eof())
    }
    fn set_options(&self, value: u64) -> PyResult<u64> {
        self.access(|c| c.set_options(value))
    }
    fn use_certificate_der(&self, der: &[u8]) -> PyResult<()> {
        self.access(|c| c.use_certificate_der(der))
    }
    fn use_private_key_der(&self, der: &[u8]) -> PyResult<()> {
        self.access(|c| c.use_private_key_der(der))
    }
    fn set_ciphertext_mtu(&self, value: u32) -> PyResult<()> {
        self.access(|c| c.set_ciphertext_mtu(value))
    }
    fn data_mtu(&self) -> PyResult<usize> {
        self.access(|c| c.dtls_data_mtu())
    }
    fn request_ocsp(&self) -> PyResult<()> {
        self.access(|c| c.request_ocsp())
    }
    fn pending(&self) -> PyResult<usize> {
        self.access(|c| Ok(c.pending()))
    }
    fn cipher_names(&self) -> PyResult<Vec<String>> {
        self.access(|c| Ok(c.cipher_names()))
    }
    fn renegotiate(&self) -> PyResult<bool> {
        self.access(|c| c.request_renegotiation())
    }
    fn renegotiation_pending(&self) -> PyResult<bool> {
        self.access(|c| Ok(c.renegotiation_pending()))
    }
    fn total_renegotiations(&self) -> PyResult<i64> {
        self.access(|c| Ok(c.total_renegotiations()))
    }
    fn set_sni(&self, value: &[u8]) -> PyResult<()> {
        let value = x509::c_string(value).map_err(bridge_error)?;
        self.access(|c| c.set_sni(&value))
    }
    fn set_reference_dns_name(&self, value: &[u8]) -> PyResult<()> {
        let value = x509::c_string(value).map_err(bridge_error)?;
        self.access(|c| c.set_reference_dns_name(&value))
    }
}

#[pyfunction]
fn tls_constants(py: Python<'_>) -> PyResult<Bound<'_, PyDict>> {
    let values = PyDict::new(py);
    for (name, value) in tls::compatibility_constants() {
        values.set_item(name, value)?;
    }
    Ok(values)
}
#[pyfunction]
fn version_description(py: Python<'_>, selector: i32) -> Bound<'_, PyBytes> {
    PyBytes::new(py, &tls::version_description(selector))
}
#[pyfunction]
fn tls_capabilities() -> Vec<&'static str> {
    let mut capabilities = Vec::new();
    if !cfg!(CRYPTOGRAPHY_IS_LIBRESSL) {
        capabilities.push("keylog");
    }
    if !cfg!(any(CRYPTOGRAPHY_IS_BORINGSSL, CRYPTOGRAPHY_IS_AWSLC)) {
        capabilities.push("cookie");
    }
    if cfg!(any(
        CRYPTOGRAPHY_OPENSSL_320_OR_GREATER,
        CRYPTOGRAPHY_IS_BORINGSSL,
        CRYPTOGRAPHY_IS_AWSLC
    )) {
        capabilities.push("group_name");
    }
    capabilities
}
#[pyfunction]
fn default_verify_paths(py: Python<'_>) -> (Bound<'_, PyBytes>, Bound<'_, PyBytes>) {
    let (file, directory) = tls::default_verify_paths();
    (PyBytes::new(py, &file), PyBytes::new(py, &directory))
}
pub(super) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(tls_capabilities, module)?)?;
    module.add_function(wrap_pyfunction!(default_verify_paths, module)?)?;
    module.add_class::<PyContext>()?;
    module.add_class::<PyConnection>()?;
    module.add_class::<PySession>()?;
    module.add_function(wrap_pyfunction!(tls_constants, module)?)?;
    module.add_function(wrap_pyfunction!(version_description, module)?)?;
    module.add("TLSWantRead", module.py().get_type::<TLSWantRead>())?;
    module.add("TLSWantWrite", module.py().get_type::<TLSWantWrite>())?;
    module.add(
        "TLSWantCertificate",
        module.py().get_type::<TLSWantCertificate>(),
    )?;
    module.add("TLSClosed", module.py().get_type::<TLSClosed>())?;
    module.add("TLSSystemError", module.py().get_type::<TLSSystemError>())?;
    Ok(())
}
