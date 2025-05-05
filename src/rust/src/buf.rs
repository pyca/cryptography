// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

use std::slice;

use pyo3::types::{IntoPyDict, PyAnyMethods};

use crate::types;

fn _extract_buffer_length<'p>(
    pyobj: &pyo3::Bound<'p, pyo3::PyAny>,
    mutable: bool,
) -> pyo3::PyResult<(pyo3::Bound<'p, pyo3::PyAny>, usize)> {
    let py = pyobj.py();
    let bufobj = if mutable {
        let kwargs = [(pyo3::intern!(py, "require_writable"), true)].into_py_dict(py)?;
        types::FFI_FROM_BUFFER
            .get(py)?
            .call((pyobj,), Some(&kwargs))
    } else {
        types::FFI_FROM_BUFFER.get(py)?.call1((pyobj,))
    }
    .map_err(|_| {
        let errmsg = if pyobj.is_instance_of::<pyo3::types::PyString>() {
            format!(
                "Cannot convert \"{}\" instance to a buffer.\nDid you mean to pass a bytestring instead?",
                pyobj.get_type()
            )
        } else {
            format!("Cannot convert \"{}\" instance to a buffer.", pyobj.get_type())
        };
        pyo3::exceptions::PyTypeError::new_err(errmsg)
    })?;
    let ptrval = types::FFI_CAST
        .get(py)?
        .call1((pyo3::intern!(py, "uintptr_t"), bufobj.clone()))?
        .call_method0(pyo3::intern!(py, "__int__"))?
        .extract::<usize>()?;
    Ok((bufobj, ptrval))
}

#[cfg(Py_3_11)]
mod pybuffer_impl {
    use pyo3::buffer::PyBuffer;
    use pyo3::types::{PyAnyMethods, PyBytes};
    use std::slice;

    pub(crate) struct CffiBuf<'p> {
        pyobj: pyo3::Bound<'p, pyo3::PyAny>,
        _bufobj: PyBuffer<u8>,
        buf: &'p [u8],
    }

    impl<'a> CffiBuf<'a> {
        pub(crate) fn from_bytes(py: pyo3::Python<'a>, buf: &'a [u8]) -> Self {
            let py_bytes = PyBytes::new(py, buf);
            let pybuffer = PyBuffer::<u8>::get(&py_bytes)
                .expect("Cannot convert \"bytes\" instance to a buffer.");
            CffiBuf {
                pyobj: py.None().into_bound(py),
                _bufobj: pybuffer,
                buf,
            }
        }

        pub(crate) fn as_bytes(&self) -> &[u8] {
            self.buf
        }

        pub(crate) fn into_pyobj(self) -> pyo3::Bound<'a, pyo3::PyAny> {
            self.pyobj
        }
    }

    impl<'a> pyo3::conversion::FromPyObject<'a> for CffiBuf<'a> {
        fn extract_bound(pyobj: &pyo3::Bound<'a, pyo3::PyAny>) -> pyo3::PyResult<Self> {
            let bufobj = PyBuffer::<u8>::get(pyobj).map_err(|_| {
                let errmsg = if pyobj.is_instance_of::<pyo3::types::PyString>() {
                    format!(
                        "Cannot convert \"{}\" instance to a buffer.\nDid you mean to pass a bytestring instead?",
                        pyobj.get_type()
                    )
                } else {
                    format!("Cannot convert \"{}\" instance to a buffer.", pyobj.get_type())
                };
                pyo3::exceptions::PyTypeError::new_err(errmsg)
            })?;
            let len = bufobj.len_bytes();
            let buf = if len == 0 {
                &[]
            } else {
                // SAFETY: pyo3::buffer::PyBuffer ensures that we have a valid ptr
                // and length (and we ensure we meet slice's requirements for
                // 0-length slices above), we're keeping pyobj alive which ensures
                // the buffer is valid. But! There is no actually guarantee
                // against concurrent mutation. See
                // https://alexgaynor.net/2022/oct/23/buffers-on-the-edge/
                // for details. This is the same as our cffi status quo ante, so
                // we're doing an unsound thing and living with it.
                unsafe { slice::from_raw_parts(bufobj.buf_ptr() as *const u8, len) }
            };

            Ok(CffiBuf {
                pyobj: pyobj.clone(),
                _bufobj: bufobj,
                buf,
            })
        }
    }
}

#[cfg(not(Py_3_11))]
mod ffi_impl {
    use super::_extract_buffer_length;
    use pyo3::types::PyAnyMethods;
    use std::slice;

    pub(crate) struct CffiBuf<'p> {
        pyobj: pyo3::Bound<'p, pyo3::PyAny>,
        _bufobj: pyo3::Bound<'p, pyo3::PyAny>,
        buf: &'p [u8],
    }

    impl<'a> CffiBuf<'a> {
        pub(crate) fn from_bytes(py: pyo3::Python<'a>, buf: &'a [u8]) -> Self {
            CffiBuf {
                pyobj: py.None().into_bound(py),
                _bufobj: py.None().into_bound(py),
                buf,
            }
        }

        pub(crate) fn as_bytes(&self) -> &[u8] {
            self.buf
        }

        pub(crate) fn into_pyobj(self) -> pyo3::Bound<'a, pyo3::PyAny> {
            self.pyobj
        }
    }

    impl<'a> pyo3::conversion::FromPyObject<'a> for CffiBuf<'a> {
        fn extract_bound(pyobj: &pyo3::Bound<'a, pyo3::PyAny>) -> pyo3::PyResult<Self> {
            let (bufobj, ptrval) = _extract_buffer_length(pyobj, false)?;
            let len = bufobj.len()?;
            let buf = if len == 0 {
                &[]
            } else {
                // SAFETY: _extract_buffer_length ensures that we have a valid ptr
                // and length (and we ensure we meet slice's requirements for
                // 0-length slices above), we're keeping pyobj alive which ensures
                // the buffer is valid. But! There is no actually guarantee
                // against concurrent mutation. See
                // https://alexgaynor.net/2022/oct/23/buffers-on-the-edge/
                // for details. This is the same as our cffi status quo ante, so
                // we're doing an unsound thing and living with it.
                unsafe { slice::from_raw_parts(ptrval as *const u8, len) }
            };

            Ok(CffiBuf {
                pyobj: pyobj.clone(),
                _bufobj: bufobj,
                buf,
            })
        }
    }
}

pub(crate) struct CffiMutBuf<'p> {
    _pyobj: pyo3::Bound<'p, pyo3::PyAny>,
    _bufobj: pyo3::Bound<'p, pyo3::PyAny>,
    buf: &'p mut [u8],
}

impl CffiMutBuf<'_> {
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        self.buf
    }
}

impl<'a> pyo3::conversion::FromPyObject<'a> for CffiMutBuf<'a> {
    fn extract_bound(pyobj: &pyo3::Bound<'a, pyo3::PyAny>) -> pyo3::PyResult<Self> {
        let (bufobj, ptrval) = _extract_buffer_length(pyobj, true)?;

        let len = bufobj.len()?;
        let buf = if len == 0 {
            &mut []
        } else {
            // SAFETY: _extract_buffer_length ensures that we have a valid ptr
            // and length (and we ensure we meet slice's requirements for
            // 0-length slices above), we're keeping pyobj alive which ensures
            // the buffer is valid. But! There is no actually guarantee
            // against concurrent mutation. See
            // https://alexgaynor.net/2022/oct/23/buffers-on-the-edge/
            // for details. This is the same as our cffi status quo ante, so
            // we're doing an unsound thing and living with it.
            unsafe { slice::from_raw_parts_mut(ptrval as *mut u8, len) }
        };

        Ok(CffiMutBuf {
            _pyobj: pyobj.clone(),
            _bufobj: bufobj,
            buf,
        })
    }
}

#[cfg(Py_3_11)]
pub(crate) use pybuffer_impl::CffiBuf;

#[cfg(not(Py_3_11))]
pub(crate) use ffi_impl::CffiBuf;
