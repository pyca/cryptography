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
        assert_eq!(key.len(), 32);
        let mut ctx: Box<MaybeUninit<ffi::poly1305_state>> =
            Box::new(MaybeUninit::<ffi::poly1305_state>::uninit());

        // SAFETY: After initializing the context, unwrap the
        // `Box<MaybeUninit<poly1305_state>>` into a `Box<poly1305_state>`
        // while keeping the same memory address. See the docstring of the
        // `Poly1305State` struct above for the rationale.
        let initialized_ctx: Box<ffi::poly1305_state> = unsafe {
            ffi::CRYPTO_poly1305_init(ctx.as_mut().as_mut_ptr(), key.as_ptr());
            let raw_ctx_ptr = (*Box::into_raw(ctx)).as_mut_ptr();
            Box::from_raw(raw_ctx_ptr)
        };

        Poly1305State {
            context: initialized_ctx,
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        // SAFETY: context is valid, as is the data ptr.
        unsafe {
            ffi::CRYPTO_poly1305_update(self.context.as_mut(), data.as_ptr(), data.len());
        };
    }

    pub fn finalize(&mut self, output: &mut [u8]) {
        assert_eq!(output.len(), 16);
        // SAFETY: context is valid and we verified that the output is the
        // right length.
        unsafe { ffi::CRYPTO_poly1305_finish(self.context.as_mut(), output.as_mut_ptr()) };
    }
}
