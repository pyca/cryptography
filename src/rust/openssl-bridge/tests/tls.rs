use openssl_bridge::{
    containers::parse_pkcs12,
    tls::{
        Callbacks, Connection, ConnectionInfo, Context, ContextBuilder, IoError, PeerVerification,
        Protocol, Role,
    },
    Error,
};

fn server() -> Context {
    server_builder().finish()
}
fn server_builder() -> ContextBuilder {
    let parsed = parse_pkcs12(
        include_bytes!("vectors/cert-key-aes256cbc.p12"),
        Some(c"cryptography"),
    )
    .unwrap();
    let mut builder = ContextBuilder::new(Protocol::Tls, PeerVerification::None).unwrap();
    builder
        .use_certificate_der(include_bytes!("vectors/tls-localhost.der"))
        .unwrap();
    builder
        .use_private_key_der(parsed.private_key.unwrap().as_ref())
        .unwrap();
    builder.check_private_key().unwrap();
    builder
}

fn client(trust: bool) -> Context {
    let policy = if trust {
        PeerVerification::Chain {
            require_certificate: true,
            once: false,
        }
    } else {
        PeerVerification::None
    };
    let mut builder = ContextBuilder::new(Protocol::Tls, policy).unwrap();
    if trust {
        builder
            .add_trusted_certificate_der(include_bytes!("vectors/tls-ca.der"))
            .unwrap();
        builder.set_verification_time(1_800_000_000).unwrap();
    }
    builder.finish()
}

fn transfer(from: &mut Connection, to: &mut Connection) {
    let mut buffer = [0; 8192];
    loop {
        match from.drain_ciphertext(&mut buffer) {
            Ok(length) => assert_eq!(to.feed_ciphertext(&buffer[..length]).unwrap(), length),
            Err(IoError::WantRead) => return,
            outcome => panic!("transport error: {outcome:?}"),
        }
    }
}

fn handshake(client: &mut Connection, server: &mut Connection) {
    let (mut client_done, mut server_done) = (false, false);
    for _ in 0..32 {
        if !client_done {
            match client.handshake() {
                Ok(()) => client_done = true,
                Err(IoError::WantRead | IoError::WantWrite) => (),
                result => panic!("client handshake: {result:?}"),
            }
        }
        transfer(client, server);
        if !server_done {
            match server.handshake() {
                Ok(()) => server_done = true,
                Err(IoError::WantRead | IoError::WantWrite) => (),
                result => panic!("server handshake: {result:?}"),
            }
        }
        transfer(server, client);
        if client_done && server_done {
            return;
        }
    }
    panic!("handshake did not complete");
}

#[test]
fn memory_handshake_authenticated_identity_data_and_shutdown() {
    let mut client = Connection::memory(client(true), Role::Client).unwrap();
    let mut server = Connection::memory(server(), Role::Server).unwrap();
    client.set_reference_dns_name(c"localhost").unwrap();
    handshake(&mut client, &mut server);
    assert_eq!(client.client_random(), server.client_random());
    assert_eq!(client.server_random(), server.server_random());
    assert_ne!(client.client_random(), client.server_random());
    assert_ne!(client.client_random(), Some([0; 32]));
    assert_ne!(server.server_random(), Some([0; 32]));
    assert!(client.set_role(Role::Server).is_err());
    assert!(client.set_sni(c"too-late.example").is_err());
    assert_eq!(client.write(b"a secret message").unwrap(), 16);
    transfer(&mut client, &mut server);
    let mut read = [0; 32];
    assert_eq!(server.read(&mut read, true).unwrap(), 16);
    assert_eq!(&read[..16], b"a secret message");
    assert_eq!(server.read(&mut read, false).unwrap(), 16);
    assert_eq!(&read[..16], b"a secret message");
    assert!(matches!(
        server.read(&mut read, false),
        Err(IoError::WantRead)
    ));
    assert!(!client.shutdown().unwrap());
    transfer(&mut client, &mut server);
    assert!(matches!(
        server.read(&mut read, false),
        Err(IoError::Closed)
    ));
    assert!(server.shutdown().unwrap());
    transfer(&mut server, &mut client);
    assert!(client.shutdown().unwrap());
}

#[test]
fn write_retries_own_input_and_reject_changed_contents() {
    let mut client = Connection::memory(client(false), Role::Client).unwrap();
    let mut server = Connection::memory(server(), Role::Server).unwrap();
    let mut source = b"retained bytes".to_vec();
    assert!(matches!(client.write(&source), Err(IoError::WantRead)));
    source.fill(0);
    assert!(matches!(
        client.write(&source),
        Err(IoError::Failure(Error::InvalidState(_)))
    ));
    assert!(matches!(
        client.handshake(),
        Err(IoError::Failure(Error::InvalidState(_)))
    ));
    assert!(matches!(
        client.shutdown(),
        Err(IoError::Failure(Error::InvalidState(_)))
    ));
    for _ in 0..32 {
        transfer(&mut client, &mut server);
        match server.handshake() {
            Ok(()) | Err(IoError::WantRead | IoError::WantWrite) => (),
            result => panic!("{result:?}"),
        }
        transfer(&mut server, &mut client);
        match client.write(b"retained bytes") {
            Ok(14) => {
                transfer(&mut client, &mut server);
                let mut result = [0; 14];
                assert_eq!(server.read(&mut result, false).unwrap(), 14);
                assert_eq!(&result, b"retained bytes");
                return;
            }
            Err(IoError::WantRead | IoError::WantWrite) => (),
            result => panic!("write retry: {result:?}"),
        }
    }
    panic!("write did not complete");
}

#[test]
fn verification_failure_poisoning_and_transport_eof() {
    let mut client = Connection::memory(client(true), Role::Client).unwrap();
    let mut server = Connection::memory(server(), Role::Server).unwrap();
    client.set_reference_dns_name(c"untrusted.example").unwrap();
    assert!(matches!(client.handshake(), Err(IoError::WantRead)));
    transfer(&mut client, &mut server);
    assert!(matches!(server.handshake(), Err(IoError::WantRead)));
    transfer(&mut server, &mut client);
    assert!(matches!(
        client.handshake(),
        Err(IoError::Failure(Error::Native(_)))
    ));
    assert!(matches!(
        client.shutdown(),
        Err(IoError::Failure(Error::InvalidState(_)))
    ));
    assert!(matches!(
        client.write(b"no"),
        Err(IoError::Failure(Error::InvalidState(_)))
    ));
    // The fatal alert remains available to the application's transport loop.
    assert!(client.drain_ciphertext(&mut [0; 4096]).unwrap() > 0);
    let mut other = Connection::memory(crate::client(false), Role::Client).unwrap();
    other.input_eof().unwrap();
    assert!(other.feed_ciphertext(b"late bytes").is_err());
    assert!(matches!(
        other.handshake(),
        Err(IoError::Failure(_)) | Err(IoError::System { .. })
    ));
}

#[cfg(unix)]
#[test]
fn sockets_keep_their_own_descriptors_alive() {
    use openssl_bridge::tls::SocketTransport;
    use std::{
        net::{TcpListener, TcpStream},
        os::fd::AsRawFd,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client_socket = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server_socket, _) = listener.accept().unwrap();
    let mut client = Connection::socket(
        client(false),
        Role::Client,
        SocketTransport::duplicate(client_socket.as_raw_fd()).unwrap(),
    )
    .unwrap();
    let mut server = Connection::socket(
        server(),
        Role::Server,
        SocketTransport::duplicate(server_socket.as_raw_fd()).unwrap(),
    )
    .unwrap();
    drop((client_socket, server_socket, listener));
    let worker = std::thread::spawn(move || {
        server.handshake().unwrap();
        let mut buffer = [0; 4];
        assert_eq!(server.read(&mut buffer, false).unwrap(), 4);
        assert_eq!(&buffer, b"live");
    });
    client.handshake().unwrap();
    assert_eq!(client.write(b"live").unwrap(), 4);
    worker.join().unwrap();
    assert!(SocketTransport::duplicate(-1).is_err());
}

#[test]
fn callbacks_select_credentials_alpn_and_copy_finished_and_ocsp() {
    use std::sync::{Arc, Mutex};
    struct Hooks {
        credentials: Context,
        events: Mutex<Vec<i32>>,
        ocsp: Mutex<Vec<u8>>,
        secrets: Mutex<usize>,
    }
    impl Callbacks for Hooks {
        fn server_name(&self, info: &ConnectionInfo) -> openssl_bridge::Result<Option<Context>> {
            assert_eq!(info.server_name.as_deref(), Some(&b"localhost"[..]));
            Ok(Some(self.credentials.clone()))
        }
        fn select_alpn(
            &self,
            _: &ConnectionInfo,
            offered: &[Vec<u8>],
        ) -> openssl_bridge::Result<Option<Vec<u8>>> {
            assert_eq!(offered, [b"h2".to_vec(), b"http/1.1".to_vec()]);
            Ok(Some(b"h2".to_vec()))
        }
        fn info(&self, _: &ConnectionInfo, event: i32, _: i32) -> openssl_bridge::Result<()> {
            self.events.lock().unwrap().push(event);
            Ok(())
        }
        fn key_log(&self, _: &ConnectionInfo, line: &[u8]) -> openssl_bridge::Result<()> {
            assert!(!line.is_empty());
            *self.secrets.lock().unwrap() += 1;
            Ok(())
        }
        fn ocsp_response(&self, _: &ConnectionInfo) -> openssl_bridge::Result<Option<Vec<u8>>> {
            Ok(Some(b"\x30\x03\x0a\x01\x06".to_vec()))
        }
        fn verify_ocsp(&self, _: &ConnectionInfo, response: &[u8]) -> openssl_bridge::Result<bool> {
            *self.ocsp.lock().unwrap() = response.to_vec();
            Ok(true)
        }
    }
    let hooks = Arc::new(Hooks {
        credentials: server(),
        events: Mutex::new(Vec::new()),
        ocsp: Mutex::new(Vec::new()),
        secrets: Mutex::new(0),
    });
    let mut builder = ContextBuilder::new(Protocol::Tls, PeerVerification::None).unwrap();
    #[cfg(not(backend = "libressl"))]
    builder.enable_key_logging().unwrap();
    #[cfg(backend = "libressl")]
    assert!(matches!(
        builder.enable_key_logging(),
        Err(Error::Unsupported(_))
    ));
    builder.set_alpn_protocols(&[b"h2", b"http/1.1"]).unwrap();
    let mut client = Connection::memory(builder.finish(), Role::Client).unwrap();
    client.set_sni(c"localhost").unwrap();
    client.request_ocsp().unwrap();
    client.set_callbacks(hooks.clone()).unwrap();
    // This factory has no credentials. The SNI callback must switch to an owned,
    // frozen factory that contains the certificate and its matching private key.
    let mut server = Connection::memory(
        ContextBuilder::new(Protocol::Tls, PeerVerification::None)
            .unwrap()
            .finish(),
        Role::Server,
    )
    .unwrap();
    server.set_callbacks(hooks.clone()).unwrap();
    handshake(&mut client, &mut server);
    assert_eq!(client.info().alpn, b"h2");
    assert_eq!(server.info().alpn, b"h2");
    assert_eq!(*hooks.ocsp.lock().unwrap(), b"\x30\x03\x0a\x01\x06");
    assert!(!hooks.events.lock().unwrap().is_empty());
    #[cfg(not(backend = "libressl"))]
    assert!(*hooks.secrets.lock().unwrap() > 0);
    #[cfg(backend = "libressl")]
    assert_eq!(*hooks.secrets.lock().unwrap(), 0);
    assert!(!client.finished_message(false).is_empty());
    assert_eq!(
        client.finished_message(false),
        server.finished_message(true)
    );
    assert_eq!(
        server.finished_message(false),
        client.finished_message(true)
    );
    assert_eq!(
        client.peer_certificate_der().unwrap().unwrap(),
        include_bytes!("vectors/tls-localhost.der")
    );
    assert_eq!(
        server.certificate_der().unwrap().unwrap(),
        include_bytes!("vectors/tls-localhost.der")
    );
    assert_eq!(client.verification_chain_der().unwrap().unwrap().len(), 1);
    assert_eq!(
        client
            .export_keying_material(b"application binding", Some(b"context"), 32)
            .unwrap()
            .as_ref(),
        server
            .export_keying_material(b"application binding", Some(b"context"), 32)
            .unwrap()
            .as_ref()
    );
}

#[test]
fn callback_panics_and_unoffered_alpn_fail_only_the_initiating_connection() {
    use std::sync::Arc;
    struct Panic;
    impl Callbacks for Panic {
        fn info(&self, _: &ConnectionInfo, _: i32, _: i32) -> openssl_bridge::Result<()> {
            panic!("application panic");
        }
    }
    let context = client(false);
    let mut failed = Connection::memory(context.clone(), Role::Client).unwrap();
    failed.set_callbacks(Arc::new(Panic)).unwrap();
    assert!(matches!(
        failed.handshake(),
        Err(IoError::Failure(Error::InvalidState(
            "TLS callback panicked"
        )))
    ));
    assert!(matches!(
        failed.handshake(),
        Err(IoError::Failure(Error::InvalidState(_)))
    ));
    let mut good = Connection::memory(context, Role::Client).unwrap();
    let mut peer = Connection::memory(server(), Role::Server).unwrap();
    handshake(&mut good, &mut peer);

    struct InvalidAlpn;
    impl Callbacks for InvalidAlpn {
        fn select_alpn(
            &self,
            _: &ConnectionInfo,
            _: &[Vec<u8>],
        ) -> openssl_bridge::Result<Option<Vec<u8>>> {
            Ok(Some(b"not offered".to_vec()))
        }
    }
    let mut client = Connection::memory(crate::client(false), Role::Client).unwrap();
    client.set_alpn_protocols(&[b"h2"]).unwrap();
    let mut server = Connection::memory(server(), Role::Server).unwrap();
    server.set_callbacks(Arc::new(InvalidAlpn)).unwrap();
    assert!(matches!(client.handshake(), Err(IoError::WantRead)));
    transfer(&mut client, &mut server);
    assert!(matches!(
        server.handshake(),
        Err(IoError::Failure(Error::InvalidInput(_)))
    ));
    assert!(server.shutdown().is_err());
}

#[test]
fn sessions_bind_factory_reference_identity_and_verification_policy() {
    let mut client_builder = ContextBuilder::new(
        Protocol::Tls,
        PeerVerification::Chain {
            require_certificate: true,
            once: false,
        },
    )
    .unwrap();
    client_builder.set_max_version(0x303).unwrap();
    client_builder
        .add_trusted_certificate_der(include_bytes!("vectors/tls-ca.der"))
        .unwrap();
    client_builder.set_verification_time(1_800_000_000).unwrap();
    let client_context = client_builder.finish();
    let mut server_builder = server_builder();
    server_builder.set_max_version(0x303).unwrap();
    server_builder
        .set_session_id_context(b"bridge tests")
        .unwrap();
    let server_context = server_builder.finish();
    let mut client = Connection::memory(client_context.clone(), Role::Client).unwrap();
    client.set_reference_dns_name(c"localhost").unwrap();
    let mut server = Connection::memory(server_context.clone(), Role::Server).unwrap();
    handshake(&mut client, &mut server);
    let original_secret = client.master_secret().unwrap().unwrap();
    let mut session = client.session().unwrap();
    let mut resumed = Connection::memory(client_context.clone(), Role::Client).unwrap();
    // A missing or changed reference identity cannot bypass validation by reusing
    // an already authenticated session. Neither can a changed verification mode.
    assert!(resumed.set_session(&mut session).is_err());
    resumed.set_reference_dns_name(c"other.example").unwrap();
    assert!(resumed.set_session(&mut session).is_err());
    resumed.set_reference_dns_name(c"localhost").unwrap();
    resumed.set_session(&mut session).unwrap();
    assert!(resumed.set_reference_dns_name(c"other.example").is_err());
    assert!(resumed
        .set_peer_verification(PeerVerification::None)
        .is_err());
    let mut peer = Connection::memory(server_context, Role::Server).unwrap();
    handshake(&mut resumed, &mut peer);
    assert_eq!(
        resumed.master_secret().unwrap().unwrap().as_ref(),
        original_secret.as_ref()
    );
    let mut different_factory = Connection::memory(crate::client(true), Role::Client).unwrap();
    different_factory
        .set_reference_dns_name(c"localhost")
        .unwrap();
    assert!(different_factory.set_session(&mut session).is_err());
}

fn dtls_server() -> Context {
    let parsed = parse_pkcs12(
        include_bytes!("vectors/cert-key-aes256cbc.p12"),
        Some(c"cryptography"),
    )
    .unwrap();
    let mut builder = ContextBuilder::new(Protocol::Dtls, PeerVerification::None).unwrap();
    #[cfg(not(any(backend = "boringssl", backend = "awslc")))]
    builder.enable_cookie_callbacks().unwrap();
    builder
        .use_certificate_der(include_bytes!("vectors/tls-localhost.der"))
        .unwrap();
    builder
        .use_private_key_der(parsed.private_key.unwrap().as_ref())
        .unwrap();
    builder
        .set_cipher_list(c"ECDHE-ECDSA-AES128-GCM-SHA256")
        .unwrap();
    builder.finish()
}
fn dtls_client() -> Context {
    let mut builder = ContextBuilder::new(
        Protocol::Dtls,
        PeerVerification::Chain {
            require_certificate: true,
            once: false,
        },
    )
    .unwrap();
    builder
        .add_trusted_certificate_der(include_bytes!("vectors/tls-ca.der"))
        .unwrap();
    builder.set_verification_time(1_800_000_000).unwrap();
    builder
        .set_cipher_list(c"ECDHE-ECDSA-AES128-GCM-SHA256")
        .unwrap();
    builder.finish()
}

#[test]
fn dtls_packets_handshake_plaintext_mtu_and_timer() {
    let mut client = Connection::datagrams(dtls_client(), Role::Client, 1200).unwrap();
    let mut server = Connection::datagrams(dtls_server(), Role::Server, 1200).unwrap();
    assert!(client.dtls_timeout().unwrap().is_none());
    assert!(!client.dtls_handle_timeout().unwrap());
    client.set_reference_dns_name(c"localhost").unwrap();
    assert!(client.dtls_data_mtu().is_err());
    assert!(matches!(client.handshake(), Err(IoError::WantRead)));
    assert!(client.dtls_timeout().unwrap().is_some());
    assert!(matches!(
        client.drain_ciphertext(&mut [0; 1]),
        Err(IoError::Failure(Error::InvalidInput(_)))
    ));
    transfer(&mut client, &mut server);
    handshake(&mut client, &mut server);
    if client.info().version == 0xfefd {
        assert_eq!(client.dtls_data_mtu().unwrap(), 1200 - 37);
    }
    let plaintext = vec![0xa5; client.dtls_data_mtu().unwrap()];
    assert_eq!(client.write(&plaintext).unwrap(), plaintext.len());
    let mut packet = [0; 65535];
    let size = client.drain_ciphertext(&mut packet).unwrap();
    assert_eq!(size, 1200);
    assert!(matches!(
        client.drain_ciphertext(&mut packet),
        Err(IoError::WantRead)
    ));
    server.feed_ciphertext(&packet[..size]).unwrap();
    let mut decoded = [0; 2000];
    let size = server.read(&mut decoded, false).unwrap();
    assert_eq!(&decoded[..size], plaintext);
    assert!(server.dtls_listen().is_err());
}

#[test]
#[cfg(not(any(backend = "boringssl", backend = "awslc")))]
fn dtls_cookie_exchange_preserves_mtu_and_packet_peek() {
    use std::sync::Arc;
    struct Cookies;
    impl Callbacks for Cookies {
        fn generate_cookie(&self, _: &ConnectionInfo) -> openssl_bridge::Result<Vec<u8>> {
            Ok(b"test-only-peer-cookie".to_vec())
        }
        fn verify_cookie(&self, _: &ConnectionInfo, cookie: &[u8]) -> openssl_bridge::Result<bool> {
            Ok(cookie == b"test-only-peer-cookie")
        }
    }
    let mut client = Connection::datagrams(dtls_client(), Role::Client, 1200).unwrap();
    let mut server = Connection::datagrams(dtls_server(), Role::Server, 1200).unwrap();
    server.set_callbacks(Arc::new(Cookies)).unwrap();
    client.set_reference_dns_name(c"localhost").unwrap();
    let mut listening = true;
    let (mut client_done, mut server_done) = (false, false);
    for _ in 0..40 {
        if !client_done {
            match client.handshake() {
                Ok(()) => client_done = true,
                Err(IoError::WantRead | IoError::WantWrite) => (),
                error => panic!("client: {error:?}"),
            }
        }
        transfer(&mut client, &mut server);
        if listening {
            match server.dtls_listen() {
                Ok(()) => listening = false,
                Err(IoError::WantRead | IoError::WantWrite) => (),
                error => panic!("listen: {error:?}"),
            }
        }
        if !listening && !server_done {
            match server.handshake() {
                Ok(()) => server_done = true,
                Err(IoError::WantRead | IoError::WantWrite) => (),
                error => panic!("server: {error:?}"),
            }
        }
        transfer(&mut server, &mut client);
        if client_done && server_done {
            break;
        }
    }
    assert!(client_done && server_done);
    server.write(b"after cookie exchange").unwrap();
    transfer(&mut server, &mut client);
    let mut output = [0; 64];
    let length = client.read(&mut output, false).unwrap();
    assert_eq!(&output[..length], b"after cookie exchange");
}

#[test]
fn frozen_context_store_remains_usable_for_independent_verification() {
    let context = client(true);
    let mut connection = Connection::memory(context.clone(), Role::Client).unwrap();
    let worker = std::thread::spawn(move || {
        for _ in 0..8 {
            let chain = context
                .verify_certificate(include_bytes!("vectors/tls-localhost.der"), &[])
                .unwrap();
            assert_eq!(chain.len(), 2);
            assert_eq!(chain[0], include_bytes!("vectors/tls-localhost.der"));
        }
    });
    let mut server = Connection::memory(server(), Role::Server).unwrap();
    handshake(&mut connection, &mut server);
    worker.join().unwrap();
}

#[test]
fn callbacks_cannot_destroy_parent_error_queue_or_errno() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    struct DrainErrors(Arc<AtomicBool>);
    impl Callbacks for DrainErrors {
        fn info(&self, _: &ConnectionInfo, _: i32, _: i32) -> openssl_bridge::Result<()> {
            if !openssl_bridge::error::take_error_queue().is_empty() {
                self.0.store(true, Ordering::Relaxed);
            }
            assert!(std::fs::File::open("/openssl-bridge/nonexistent/callback-file").is_err());
            Ok(())
        }
    }
    let failure = |hooks: Option<Arc<dyn Callbacks>>| {
        let mut connection = Connection::memory(server(), Role::Server).unwrap();
        if let Some(hooks) = hooks {
            connection.set_callbacks(hooks).unwrap();
        }
        connection
            .feed_ciphertext(b"GET / HTTP/1.0\r\n\r\n")
            .unwrap();
        match connection.handshake() {
            Err(IoError::Failure(Error::Native(errors))) => errors,
            result => panic!("expected TLS protocol failure: {result:?}"),
        }
    };
    let expected = failure(None);
    assert!(!expected.is_empty());
    let drained = Arc::new(AtomicBool::new(false));
    let actual = failure(Some(Arc::new(DrainErrors(drained.clone()))));
    assert_eq!(actual, expected);
    // The callback must see an empty isolated queue even when native SSL has
    // recorded the protocol error before invoking its final info callback.
    assert!(!drained.load(Ordering::Relaxed));
}

#[test]
fn ca_names_are_copied_during_certificate_selection() {
    use openssl_bridge::x509::{Certificate, Encoding, NameField};
    let mut ca = Certificate::decode(include_bytes!("vectors/tls-ca.der"), Encoding::Der).unwrap();
    let names = vec![ca.name(NameField::Subject).unwrap().der().unwrap()];
    for maximum in [0x303, 0x304] {
        let mut builder = server_builder();
        builder.set_max_version(maximum).unwrap();
        if cfg!(backend = "libressl") && maximum == 0x304 {
            assert!(matches!(
                builder.set_client_ca_names(&names),
                Err(Error::Unsupported(_))
            ));
            continue;
        }
        builder.set_peer_verification(PeerVerification::Chain {
            require_certificate: false,
            once: false,
        });
        builder.set_client_ca_names(&names).unwrap();
        if cfg!(backend = "libressl") {
            assert!(matches!(
                builder.set_max_version(0),
                Err(Error::Unsupported(_))
            ));
            assert!(matches!(
                builder.set_max_version(0x304),
                Err(Error::Unsupported(_))
            ));
        }
        let mut server = Connection::memory(builder.finish(), Role::Server).unwrap();
        let mut client = Connection::memory(client(true), Role::Client).unwrap();
        assert!(client.client_ca_names_der().unwrap().is_empty());
        handshake(&mut client, &mut server);
        assert_eq!(client.client_ca_names_der().unwrap(), names);
        assert_eq!(server.client_ca_names_der().unwrap(), names);
    }
}

#[test]
fn ocsp_observers_are_not_called_without_a_request() {
    struct UnexpectedOcsp;
    impl Callbacks for UnexpectedOcsp {
        fn ocsp_response(&self, _: &ConnectionInfo) -> openssl_bridge::Result<Option<Vec<u8>>> {
            Err(Error::InvalidState("unsolicited OCSP server callback"))
        }
        fn verify_ocsp(&self, _: &ConnectionInfo, _: &[u8]) -> openssl_bridge::Result<bool> {
            Err(Error::InvalidState("unsolicited OCSP client callback"))
        }
    }
    let mut client = Connection::memory(client(true), Role::Client).unwrap();
    let mut server = Connection::memory(server(), Role::Server).unwrap();
    client
        .set_callbacks(std::sync::Arc::new(UnexpectedOcsp))
        .unwrap();
    server
        .set_callbacks(std::sync::Arc::new(UnexpectedOcsp))
        .unwrap();
    handshake(&mut client, &mut server);
}

#[test]
fn default_callbacks_preserve_verification_and_decline_optional_protocols() {
    struct Defaults;
    impl Callbacks for Defaults {}
    let mut connection = Connection::memory(client(false), Role::Client).unwrap();
    let info = connection.info();
    assert!(Defaults.verify(&info, &[], 0, 0, true).unwrap());
    assert!(!Defaults.verify(&info, &[], 1, 0, false).unwrap());
    assert!(Defaults.server_name(&info).unwrap().is_none());
    assert!(Defaults
        .select_alpn(&info, &[b"h2".to_vec()])
        .unwrap()
        .is_none());
    Defaults.info(&info, 0, 0).unwrap();
    Defaults.key_log(&info, b"line").unwrap();
    assert!(Defaults.ocsp_response(&info).unwrap().is_none());
    assert!(Defaults.verify_ocsp(&info, &[]).unwrap());
    assert!(Defaults.generate_cookie(&info).is_err());
    assert!(!Defaults.verify_cookie(&info, b"untrusted").unwrap());
}

#[test]
fn context_configuration_bounds_and_unconnected_metadata() {
    use openssl_bridge::tls::ShutdownState;
    assert!(!openssl_bridge::tls::version_description(0).is_empty());
    let _ = openssl_bridge::tls::default_verify_paths();
    let mut builder = ContextBuilder::new(Protocol::Tls, PeerVerification::None).unwrap();
    assert!(builder.set_alpn_protocols(&[b""]).is_err());
    assert!(builder.set_alpn_protocols(&[&[1; 256]]).is_err());
    assert!(builder
        .set_alpn_protocols(&vec![&[1u8; 255][..]; 257])
        .is_err());
    assert!(builder.set_verify_depth(u32::MAX).is_err());
    assert!(builder.set_session_timeout(u32::MAX).is_err());
    assert!(builder.set_groups(c"not-a-group").is_err());
    assert!(builder.set_srtp_profiles(c"not-a-profile").is_err());
    let suites = builder.set_tls13_ciphersuites(c"TLS_AES_128_GCM_SHA256");
    assert_eq!(
        suites.is_ok(),
        openssl_bridge::BACKEND != openssl_bridge::Backend::BoringSsl
    );
    let context = builder.finish();
    assert!(context.certificate_der().is_none());
    assert_eq!(
        server().certificate_der().unwrap(),
        include_bytes!("vectors/tls-localhost.der")
    );
    let mut connection = Connection::memory(context, Role::Client).unwrap();
    assert_eq!(connection.pending(), 0);
    assert!(connection.peer_certificate_der().unwrap().is_none());
    assert!(connection.peer_chain_der().unwrap().is_none());
    assert!(connection.finished_message(false).is_empty());
    assert!(connection.finished_message(true).is_empty());
    for state in [
        ShutdownState::Open,
        ShutdownState::Sent,
        ShutdownState::Received,
        ShutdownState::Both,
    ] {
        connection.set_shutdown_state(state).unwrap();
        assert_eq!(connection.shutdown_state(), state);
    }
    assert!(!connection.renegotiation_pending());
    assert_eq!(connection.total_renegotiations(), 0);
}
