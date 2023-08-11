// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::mem::MaybeUninit;

pub struct Poly1305State {
    // The state data must be allocated in the heap so that its address does not change. This is
    // because BoringSSL APIs that take a `poly1305_state*` ignore all the data before an aligned
    // address. Since a stack-allocated struct would change address on every copy, BoringSSL would
    // interpret each copy differently, causing unexpected behavior.
    context: Box<ffi::poly1305_state>,
}

impl Poly1305State {
    pub fn new(key: &[u8]) -> Poly1305State {
        #[cfg(CRYPTOGRAPHY_IS_BORINGSSL)]
        let mut ctx: Box<ffi::poly1305_state> = Box::new([0; 512usize]);
        #[cfg(CRYPTOGRAPHY_IS_LIBRESSL)]
        let mut ctx: Box<ffi::poly1305_state> = Box::new(ffi::poly1305_state {
            aligner: 0,
            opaque: [0; 136usize],
        });

        unsafe {
            ffi::CRYPTO_poly1305_init(ctx.as_mut(), key.as_ptr());
        }
        Poly1305State { context: ctx }
    }

    pub fn update(&mut self, data: &[u8]) -> () {
        unsafe {
            ffi::CRYPTO_poly1305_update(self.context.as_mut(), data.as_ptr(), data.len());
        };
    }

    pub fn finalize(&mut self, output: &mut [u8]) -> () {
        unsafe { ffi::CRYPTO_poly1305_finish(self.context.as_mut(), output.as_mut_ptr()) };
    }
}
