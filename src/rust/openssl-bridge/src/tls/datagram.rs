//! Packet-preserving ciphertext transport. Native BIOs own independent Arc
//! references; callbacks never borrow a Rust Connection through a raw pointer.
use super::{Connection, Context, IoError, IoResult, Protocol, Role, Transport};
use crate::{
    error::{check, pointer},
    ffi, Error, Result,
};
use std::{
    collections::VecDeque,
    ffi::{c_char, c_int, c_long, c_void},
    panic::{catch_unwind, AssertUnwindSafe},
    ptr::NonNull,
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

const MAX_PACKET: usize = 65535;
const MAX_BUFFER: usize = 1024 * 1024;
#[derive(Default)]
struct Packets {
    packets: VecDeque<Vec<u8>>,
    bytes: usize,
    mtu: u32,
    peek: bool,
    eof: bool,
}
#[derive(Clone)]
pub(super) struct Queue(Arc<Mutex<Packets>>);
impl Queue {
    pub(super) fn feed(&self, data: &[u8]) -> IoResult<usize> {
        if data.is_empty() {
            return Ok(0);
        }
        if data.len() > MAX_PACKET {
            return Err(Error::InvalidInput("DTLS datagram exceeds 65535 bytes").into());
        }
        let mut state = self
            .0
            .lock()
            .map_err(|_| Error::InvalidState("DTLS transport failed"))?;
        if state.eof {
            return Err(Error::InvalidState("DTLS transport has reached EOF").into());
        }
        if state.bytes + data.len() > MAX_BUFFER {
            return Err(IoError::WantWrite);
        }
        state.packets.push_back(data.to_vec());
        state.bytes += data.len();
        Ok(data.len())
    }
    pub(super) fn drain(&self, output: &mut [u8]) -> IoResult<usize> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| Error::InvalidState("DTLS transport failed"))?;
        let packet = state.packets.front().ok_or(IoError::WantRead)?;
        if output.len() < packet.len() {
            return Err(
                Error::InvalidInput("DTLS output buffer must hold the whole datagram").into(),
            );
        }
        let length = packet.len();
        output[..length].copy_from_slice(packet);
        state.packets.pop_front();
        state.bytes -= length;
        Ok(length)
    }
    pub(super) fn eof(&self) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| Error::InvalidState("DTLS transport failed"))?
            .eof = true;
        Ok(())
    }
    fn mtu(&self, mtu: u32) -> Result<()> {
        self.0
            .lock()
            .map_err(|_| Error::InvalidState("DTLS transport failed"))?
            .mtu = mtu;
        Ok(())
    }
}

struct Method(NonNull<ffi::BIO_METHOD>);
struct DatagramBio(NonNull<ffi::BIO>);
impl Drop for DatagramBio {
    fn drop(&mut self) {
        // SAFETY: This guard owns one custom BIO reference before SSL_set_bio
        // transfers it. Its destructor releases the queue's native Arc count.
        unsafe {
            ffi::BIO_free(self.0.as_ptr());
        }
    }
}
// SAFETY: Initialized once before publication and never mutated or freed.
unsafe impl Send for Method {}
// SAFETY: Concurrent BIO creation only reads the permanently frozen descriptor.
unsafe impl Sync for Method {}
fn method() -> Result<&'static Method> {
    static METHOD: OnceLock<Result<Method>> = OnceLock::new();
    METHOD
        .get_or_init(|| {
            // SAFETY: Allocate a new custom method index and descriptor; callbacks
            // are installed before the descriptor is shared with any BIO.
            unsafe {
                let index = ffi::BIO_get_new_index();
                if index < 0 {
                    return Err(Error::capture());
                }
                let method = pointer(ffi::BIO_meth_new(
                    index | ffi::BIO_TYPE_SOURCE_SINK as i32,
                    c"openssl-bridge datagrams".as_ptr(),
                ))?;
                let result = (|| {
                    check(ffi::BIO_meth_set_create(method.as_ptr(), Some(create)))?;
                    check(ffi::BIO_meth_set_destroy(method.as_ptr(), Some(destroy)))?;
                    check(ffi::BIO_meth_set_read(method.as_ptr(), Some(read)))?;
                    check(ffi::BIO_meth_set_write(method.as_ptr(), Some(write)))?;
                    check(ffi::BIO_meth_set_ctrl(method.as_ptr(), Some(control)))
                })();
                if let Err(error) = result {
                    ffi::BIO_meth_free(method.as_ptr());
                    return Err(error);
                }
                // A single small method descriptor intentionally has process lifetime.
                Ok(Method(method))
            }
        })
        .as_ref()
        .map_err(Clone::clone)
}
fn bio(mtu: u32) -> Result<(DatagramBio, Queue)> {
    // SAFETY: The immutable method has process lifetime; BIO_new owns the BIO.
    let bio = DatagramBio(pointer(unsafe { ffi::BIO_new(method()?.0.as_ptr()) })?);
    let queue = Queue(Arc::new(Mutex::new(Packets {
        mtu,
        ..Packets::default()
    })));
    // SAFETY: Transfer one Arc count to the BIO's destructor. The data pointer
    // denotes shared Mutex state, not a pointee uniquely owned by Rust.
    unsafe {
        ffi::BIO_set_data(
            bio.0.as_ptr(),
            Arc::into_raw(queue.0.clone()).cast_mut().cast(),
        )
    };
    Ok((bio, queue))
}
unsafe extern "C" fn create(bio: *mut ffi::BIO) -> c_int {
    // SAFETY: Native BIO_new supplies an exclusive, initialized allocation.
    unsafe {
        ffi::BIO_set_init(bio, 1);
    }
    1
}
unsafe extern "C" fn destroy(bio: *mut ffi::BIO) -> c_int {
    if bio.is_null() {
        return 0;
    }
    // SAFETY: Only this method installs data; destroy consumes its Arc once.
    unsafe {
        let data = ffi::BIO_get_data(bio).cast::<Mutex<Packets>>();
        ffi::BIO_set_data(bio, std::ptr::null_mut());
        if !data.is_null() {
            drop(Arc::from_raw(data));
        }
    }
    1
}
unsafe fn state<'a>(bio: *mut ffi::BIO) -> &'a Mutex<Packets> {
    // SAFETY: Called only inside callbacks on a BIO whose live Arc reference was
    // installed by bio(). That reference is retained until destroy returns.
    unsafe { &*ffi::BIO_get_data(bio).cast::<Mutex<Packets>>() }
}
unsafe extern "C" fn read(bio: *mut ffi::BIO, output: *mut c_char, length: c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if length <= 0 || output.is_null() {
            return 0;
        }
        // SAFETY: Native callback arguments supply a writable buffer and a live
        // custom BIO. No slice or mutex guard is retained after this callback.
        unsafe {
            ffi::OB_bio_clear_retry(bio);
            let Ok(mut state) = state(bio).lock() else {
                return -1;
            };
            let Some(packet) = state.packets.front() else {
                if state.eof {
                    return 0;
                }
                ffi::OB_bio_retry_read(bio);
                return -1;
            };
            let copied = packet.len().min(length as usize);
            std::ptr::copy_nonoverlapping(packet.as_ptr(), output.cast(), copied);
            if !state.peek {
                let length = packet.len();
                state.packets.pop_front();
                state.bytes -= length;
            }
            copied as i32
        }
    }))
    .unwrap_or(-1)
}
unsafe extern "C" fn write(bio: *mut ffi::BIO, input: *const c_char, length: c_int) -> c_int {
    catch_unwind(AssertUnwindSafe(|| {
        if length <= 0 {
            return 0;
        }
        if input.is_null() || length as usize > MAX_PACKET {
            return -1;
        }
        // SAFETY: Native callback input is readable for length; copy before
        // returning. The native caller retains no pointer into the Rust queue.
        unsafe {
            ffi::OB_bio_clear_retry(bio);
            let Ok(mut state) = state(bio).lock() else {
                return -1;
            };
            if state.bytes + length as usize > MAX_BUFFER {
                ffi::OB_bio_retry_write(bio);
                return -1;
            }
            let input = std::slice::from_raw_parts(input.cast::<u8>(), length as usize);
            state.packets.push_back(input.to_vec());
            state.bytes += input.len();
            length
        }
    }))
    .unwrap_or(-1)
}
unsafe extern "C" fn control(
    bio: *mut ffi::BIO,
    command: c_int,
    argument: c_long,
    _: *mut c_void,
) -> c_long {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: This callback is registered only on live custom queue BIOs.
        let Ok(mut state) = (unsafe { state(bio) }).lock() else {
            return 0;
        };
        match command as u32 {
            ffi::BIO_CTRL_RESET => {
                state.packets.clear();
                state.bytes = 0;
                1
            }
            ffi::BIO_CTRL_EOF => c_long::from(state.eof && state.packets.is_empty()),
            ffi::BIO_CTRL_PENDING => state.packets.front().map_or(0, |p| p.len() as c_long),
            ffi::BIO_CTRL_WPENDING => 0,
            ffi::BIO_CTRL_FLUSH => 1,
            // SAFETY: Pure translation of fork-specific numeric macro values.
            _ => match unsafe { ffi::OB_dgram_control_kind(command) } {
                // MTUs are restricted to 256..=65535, including on Windows.
                1 => state.mtu as c_long,
                2 if (256..=65535).contains(&argument) => {
                    state.mtu = argument as u32;
                    argument
                }
                3 => {
                    state.peek = argument != 0;
                    1
                }
                4 => 1, // Timer scheduling belongs to the caller's event loop.
                5 => 0, // MTU is ciphertext payload, excluding network headers.
                _ => 0,
            },
        }
    }))
    .unwrap_or(0)
}

impl Connection {
    /// DTLS over an owned packet queue. Each feed/drain call transfers exactly
    /// one datagram. The MTU counts ciphertext bytes, excluding IP/UDP headers.
    pub fn datagrams(context: Context, role: Role, mtu: u32) -> Result<Self> {
        if context.protocol() != Protocol::Dtls {
            return Err(Error::InvalidInput("datagrams require a DTLS factory"));
        }
        validate_mtu(mtu)?;
        let native = Self::allocate(&context, role)?;
        let (input, input_queue) = bio(mtu)?;
        let (output, output_queue) = bio(mtu)?;
        // SAFETY: Transfer two distinct BIO references exactly once; the Arc
        // queues remain live through both Rust and native owners.
        unsafe {
            ffi::SSL_set_bio(native.0.as_ptr(), input.0.as_ptr(), output.0.as_ptr());
        }
        std::mem::forget(input);
        std::mem::forget(output);
        // SAFETY: Fresh, exclusive DTLS connection and validated bounded MTU.
        check(unsafe { ffi::OB_dtls_set_mtu(native.0.as_ptr(), mtu) })?;
        let callbacks = super::callbacks::CallbackState::new(context.clone());
        callbacks.attach(&native)?;
        Ok(Self {
            native,
            transport: Transport::Datagrams {
                input: input_queue,
                output: output_queue,
                mtu,
                listen_complete: false,
                listening: false,
            },
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
    pub fn set_ciphertext_mtu(&mut self, mtu: u32) -> Result<()> {
        self.ready()?;
        // MTU is transport state, not peer/session policy. Updating it after
        // a handshake is supported, but must not change a pending write's
        // already selected record sizes or retransmission buffer.
        if self.pending_write.is_some() {
            return Err(Error::InvalidState(
                "complete the pending write before changing MTU",
            ));
        }
        validate_mtu(mtu)?;
        let Transport::Datagrams {
            input,
            output,
            mtu: current,
            ..
        } = &mut self.transport
        else {
            return Err(Error::InvalidState(
                "connection does not use DTLS datagrams",
            ));
        };
        // SAFETY: Exclusive connection, valid transport, bounded MTU.
        check(unsafe { ffi::OB_dtls_set_mtu(self.native.0.as_ptr(), mtu) })?;
        input.mtu(mtu)?;
        output.mtu(mtu)?;
        *current = mtu;
        Ok(())
    }
    pub fn dtls_timeout(&mut self) -> Result<Option<Duration>> {
        self.ready()?;
        if self.context.protocol() != Protocol::Dtls {
            return Err(Error::InvalidState("connection is not DTLS"));
        }
        let mut micros = 0;
        // SAFETY: Exclusive live DTLS object and a writable integer output.
        match unsafe { ffi::OB_dtls_timeout(self.native.0.as_ptr(), &mut micros) } {
            0 => Ok(None),
            1 => Ok(Some(Duration::from_micros(micros))),
            _ => Err(Error::InvalidState("native DTLS timer is invalid")),
        }
    }
    pub fn dtls_handle_timeout(&mut self) -> IoResult<bool> {
        self.ready()?;
        if self.context.protocol() != Protocol::Dtls || self.pending_write.is_some() {
            return Err(Error::InvalidState("DTLS timer requires no pending write").into());
        }
        // SAFETY: Clear this thread's diagnostics without freezing a connection
        // whose handshake has not begun; handling an inactive timer is a no-op.
        unsafe {
            ffi::ERR_clear_error();
            ffi::OB_clear_errno();
        }
        // SAFETY: Exclusive DTLS object with no outstanding application write.
        let result = unsafe { ffi::OB_dtls_handle_timeout(self.native.0.as_ptr()) };
        self.callback_result()?;
        if result < 0 {
            self.poisoned = true;
            return Err(Error::capture().into());
        }
        Ok(result != 0)
    }
    /// Perform the server cookie exchange. The application must bind its cookie
    /// to its own transport peer identity; this abstract queue stores no address.
    pub fn dtls_listen(&mut self) -> IoResult<()> {
        self.ready()?;
        let Transport::Datagrams {
            mtu,
            listen_complete,
            listening,
            ..
        } = &self.transport
        else {
            return Err(Error::InvalidState("DTLS listen requires a datagram queue").into());
        };
        if self.role != Role::Server
            || *listen_complete
            || (self.started && !*listening)
            || self.pending_write.is_some()
        {
            return Err(Error::InvalidState("DTLS listen requires a fresh server").into());
        }
        let mtu = *mtu;
        #[cfg(any(backend = "boringssl", backend = "awslc"))]
        {
            let _ = mtu;
            Err(Error::Unsupported("native DTLS cookie exchange").into())
        }
        #[cfg(not(any(backend = "boringssl", backend = "awslc")))]
        {
            self.begin_io();
            if let Transport::Datagrams { listening, .. } = &mut self.transport {
                *listening = true;
            }
            // SAFETY: Exclusive DTLS server with queue BIOs and bounded MTU.
            let result = unsafe { ffi::OB_dtls_listen(self.native.0.as_ptr(), mtu) };
            let errno = std::io::Error::last_os_error().raw_os_error();
            if result == 0 {
                self.callback_result()?;
                return Err(IoError::WantRead);
            }
            self.classify(result, errno)?;
            if let Transport::Datagrams {
                listen_complete, ..
            } = &mut self.transport
            {
                *listen_complete = true;
            }
            Ok(())
        }
    }
    /// Maximum plaintext in a single DTLS record for the negotiated cipher.
    pub fn dtls_data_mtu(&mut self) -> Result<usize> {
        self.ready()?;
        let Transport::Datagrams { mtu, .. } = self.transport else {
            return Err(Error::InvalidState(
                "connection does not use DTLS datagrams",
            ));
        };
        // SAFETY: Query the initial handshake state of this exclusive SSL.
        if unsafe { ffi::OB_tls_handshake_complete(self.native.0.as_ptr()) } == 0 {
            return Err(Error::InvalidState("DTLS handshake is incomplete"));
        }
        // SAFETY: Exclusive established DTLS connection; returns a byte count.
        let native = unsafe { ffi::OB_dtls_data_mtu(self.native.0.as_ptr(), mtu) };
        if native != 0 {
            return Ok(native);
        }
        let info = self.info();
        if info.version != ffi::DTLS1_2_VERSION as i32 {
            return Err(Error::Unsupported("DTLS data MTU for this native protocol"));
        }
        let cipher = info
            .cipher
            .ok_or(Error::InvalidState("DTLS cipher is unavailable"))?;
        let overhead = if cipher.name.contains("GCM") {
            13 + 8 + 16
        } else if cipher.name.contains("CHACHA20") {
            13 + 16
        } else {
            return Err(Error::Unsupported("DTLS data MTU for this native cipher"));
        };
        Ok(mtu as usize - overhead)
    }
}
fn validate_mtu(mtu: u32) -> Result<()> {
    if !(256..=65535).contains(&mtu) {
        return Err(Error::InvalidInput(
            "DTLS ciphertext MTU must be 256..=65535",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_queue_preserves_boundaries_backpressure_and_eof() {
        let (native, queue) = bio(1200).unwrap();
        assert_eq!(queue.feed(&[]).unwrap(), 0);
        assert!(queue.feed(&vec![0; MAX_PACKET + 1]).is_err());
        let packet = vec![0x5a; MAX_PACKET];
        for _ in 0..MAX_BUFFER / MAX_PACKET {
            queue.feed(&packet).unwrap();
        }
        assert!(matches!(queue.feed(&packet), Err(IoError::WantWrite)));
        assert!(queue.drain(&mut [0xa5; 4]).is_err());
        let mut output = vec![0; MAX_PACKET];
        assert_eq!(queue.drain(&mut output).unwrap(), MAX_PACKET);
        assert_eq!(output, packet);
        queue.mtu(1400).unwrap();
        queue.eof().unwrap();
        assert!(queue.feed(b"after EOF").is_err());
        // Pending packets remain readable after EOF and after the native owner
        // is dropped; the queue holds an independent Arc reference.
        drop(native);
        assert_eq!(queue.drain(&mut output).unwrap(), MAX_PACKET);
    }

    #[test]
    fn native_bio_callbacks_handle_empty_truncated_and_full_packets() {
        let (native, queue) = bio(1200).unwrap();
        let p = native.0.as_ptr();
        let mut out = [0xa5; 16];
        // SAFETY: The BIO and all non-null buffers are live and exclusive.
        // Null/zero buffers exercise the callbacks' explicit no-access cases.
        unsafe {
            assert_eq!(destroy(std::ptr::null_mut()), 0);
            assert_eq!(read(p, std::ptr::null_mut(), 0), 0);
            assert_eq!(read(p, std::ptr::null_mut(), 1), 0);
            assert_eq!(read(p, out.as_mut_ptr().cast(), 16), -1);
            assert_eq!(write(p, std::ptr::null(), 0), 0);
            assert_eq!(write(p, std::ptr::null(), 1), -1);
            let oversized = vec![0; MAX_PACKET + 1];
            assert_eq!(
                write(p, oversized.as_ptr().cast(), oversized.len() as i32),
                -1
            );
            assert_eq!(write(p, b"packet".as_ptr().cast(), 6), 6);
            assert_eq!(read(p, out.as_mut_ptr().cast(), 3), 3);
            assert_eq!(&out[..3], b"pac");
            assert!(out[3..].iter().all(|b| *b == 0xa5));
            assert_eq!(read(p, out.as_mut_ptr().cast(), 16), -1);
            let packet = vec![0; MAX_PACKET];
            for _ in 0..MAX_BUFFER / MAX_PACKET {
                queue.feed(&packet).unwrap();
            }
            assert_eq!(write(p, packet.as_ptr().cast(), MAX_PACKET as i32), -1);
            assert_eq!(
                control(p, ffi::BIO_CTRL_RESET as i32, 0, std::ptr::null_mut()),
                1
            );
            queue.eof().unwrap();
            assert_eq!(read(p, out.as_mut_ptr().cast(), 16), 0);
            assert_eq!(
                control(p, ffi::BIO_CTRL_EOF as i32, 0, std::ptr::null_mut()),
                1
            );
        }
    }

    #[test]
    fn native_bio_controls_and_peek_do_not_lose_packets() {
        let (native, queue) = bio(1200).unwrap();
        let p = native.0.as_ptr();
        let mut out = [0; 8];
        queue.feed(b"packet").unwrap();
        // SAFETY: All calls use the owned BIO and bounded initialized storage.
        unsafe {
            assert_eq!(
                control(p, ffi::BIO_CTRL_PENDING as i32, 0, std::ptr::null_mut()),
                6
            );
            assert_eq!(
                control(p, ffi::BIO_CTRL_WPENDING as i32, 0, std::ptr::null_mut()),
                0
            );
            assert_eq!(
                control(p, ffi::BIO_CTRL_FLUSH as i32, 0, std::ptr::null_mut()),
                1
            );
            assert_eq!(control(p, -1, 0, std::ptr::null_mut()), 0);
            // These command numbers differ between backends. Exercise every
            // control supported by the selected headers through their shim.
            for command in 0..=200 {
                match ffi::OB_dgram_control_kind(command) {
                    1 => assert_eq!(
                        control(p, command, 0, std::ptr::null_mut()),
                        queue.0.lock().unwrap().mtu as c_long
                    ),
                    2 => {
                        assert_eq!(control(p, command, 1400, std::ptr::null_mut()), 1400);
                        assert_eq!(control(p, command, 0, std::ptr::null_mut()), 0);
                    }
                    3 => {
                        assert_eq!(control(p, command, 1, std::ptr::null_mut()), 1);
                        assert_eq!(read(p, out.as_mut_ptr().cast(), 8), 6);
                        assert_eq!(read(p, out.as_mut_ptr().cast(), 8), 6);
                        assert_eq!(control(p, command, 0, std::ptr::null_mut()), 1);
                    }
                    4 => assert_eq!(control(p, command, 0, std::ptr::null_mut()), 1),
                    5 => assert_eq!(control(p, command, 0, std::ptr::null_mut()), 0),
                    _ => {}
                }
            }
        }
        assert_eq!(queue.drain(&mut out).unwrap(), 6);
        assert_eq!(&out[..6], b"packet");
    }

    #[test]
    fn poisoned_queue_is_rejected_by_rust_and_native_entry_points() {
        let (native, queue) = bio(1200).unwrap();
        let poisoned = queue.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poisoned.0.lock().unwrap();
            panic!("simulate a failed transport operation");
        })
        .join()
        .is_err());
        assert!(queue.feed(b"packet").is_err());
        assert!(queue.drain(&mut [0; 8]).is_err());
        assert!(queue.eof().is_err());
        assert!(queue.mtu(1400).is_err());
        let mut out = [0; 8];
        // SAFETY: A poisoned mutex is still a live allocation; callbacks must
        // translate the failed lock without unwinding across the C ABI.
        unsafe {
            assert_eq!(read(native.0.as_ptr(), out.as_mut_ptr().cast(), 8), -1);
            assert_eq!(write(native.0.as_ptr(), b"packet".as_ptr().cast(), 6), -1);
            assert_eq!(
                control(
                    native.0.as_ptr(),
                    ffi::BIO_CTRL_PENDING as i32,
                    0,
                    std::ptr::null_mut()
                ),
                0
            );
        }
    }
}
