// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::{ptr, slice};

pub(crate) struct CffiBuf<'p> {
    _pyobj: &'p pyo3::PyAny,
    _bufobj: &'p pyo3::PyAny,
    buf: &'p [u8],
}

impl CffiBuf<'_> {
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.buf
    }
}

impl<'a> pyo3::conversion::FromPyObject<'a> for CffiBuf<'a> {
    fn extract(pyobj: &'a pyo3::PyAny) -> pyo3::PyResult<Self> {
        let py = pyobj.py();

        let (bufobj, ptrval): (&pyo3::PyAny, usize) = py
            .import(pyo3::intern!(py, "cryptography.utils"))?
            .call_method1(pyo3::intern!(py, "_extract_buffer_length"), (pyobj,))?
            .extract()?;

        let len = bufobj.len()?;
        let ptr = if len == 0 {
            ptr::NonNull::dangling().as_ptr()
        } else {
            ptrval as *const u8
        };

        Ok(CffiBuf {
            _pyobj: pyobj,
            _bufobj: bufobj,
            // SAFETY: _extract_buffer_length ensures that we have a valid ptr
            // and length (and we ensure we meet slice's requirements for
            // 0-length slices above), we're keeping pyobj alive which ensures
            // the buffer is valid. But! There is no actually guarantee
            // against concurrent mutation. See
            // https://alexgaynor.net/2022/oct/23/buffers-on-the-edge/
            // for details. This is the same as our cffi status quo ante, so
            // we're doing an unsound thing and living with it.
            buf: unsafe { slice::from_raw_parts(ptr, len) },
        })
    }
}
