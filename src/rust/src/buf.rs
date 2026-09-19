// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

// Rust slices never borrow Python's mutable buffer storage. Python's buffer
// protocol performs the snapshot and publication; native operations only see
// immutable bytes or exclusive Rust storage, including while the GIL is released.
#![forbid(unsafe_code)]

use openssl_bridge::secret::SecretBytes;
use pyo3::pybacked::PyBackedBytes;
use pyo3::types::{PyAnyMethods, PyBytes, PyBytesMethods, PyMemoryView, PySlice};

pub(crate) fn checked_add_length(length: usize, extra: usize) -> pyo3::PyResult<usize> {
    length
        .checked_add(extra)
        .ok_or_else(|| pyo3::exceptions::PyOverflowError::new_err("buffer length overflow"))
}

fn generate_non_convertible_buffer_error_msg(
    pyobj: &pyo3::Borrowed<'_, '_, pyo3::PyAny>,
) -> String {
    if pyobj.is_instance_of::<pyo3::types::PyString>() {
        format!(
            "Cannot convert \"{}\" instance to a buffer.\nDid you mean to pass a bytestring instead?",
            pyobj.get_type()
        )
    } else {
        format!(
            "Cannot convert \"{}\" instance to a buffer.",
            pyobj.get_type()
        )
    }
}

fn memory_view<'p>(
    pyobj: &pyo3::Borrowed<'_, 'p, pyo3::PyAny>,
    writable: bool,
) -> pyo3::PyResult<pyo3::Bound<'p, PyMemoryView>> {
    let view = PyMemoryView::from(pyobj).map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(generate_non_convertible_buffer_error_msg(pyobj))
    })?;
    if writable && view.getattr("readonly")?.extract::<bool>()? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "Buffer is not writable.",
        ));
    }
    if !view.getattr("c_contiguous")?.extract::<bool>()? {
        return Err(pyo3::exceptions::PyBufferError::new_err(
            "Buffer is not contiguous.",
        ));
    }
    Ok(view)
}

enum Input<'p> {
    Borrowed(&'p [u8]),
    Python(PyBackedBytes),
}

pub(crate) struct CffiBuf<'p> {
    pyobj: pyo3::Py<pyo3::PyAny>,
    input: Input<'p>,
}
impl<'p> CffiBuf<'p> {
    pub(crate) fn from_bytes(py: pyo3::Python<'p>, bytes: &'p [u8]) -> Self {
        Self {
            pyobj: py.None(),
            input: Input::Borrowed(bytes),
        }
    }
    pub(crate) fn as_bytes(&self) -> &[u8] {
        match &self.input {
            Input::Borrowed(bytes) => bytes,
            Input::Python(bytes) => bytes.as_ref(),
        }
    }
    pub(crate) fn into_pyobj(self, py: pyo3::Python<'p>) -> pyo3::Bound<'p, pyo3::PyAny> {
        self.pyobj.into_bound(py)
    }
}
impl<'p> CffiBuf<'p> {
    fn extract_limited(
        pyobj: pyo3::Borrowed<'_, 'p, pyo3::PyAny>,
        maximum: usize,
    ) -> pyo3::PyResult<Self> {
        let check_length = |length: usize| -> pyo3::PyResult<()> {
            if length > maximum {
                return Err(pyo3::exceptions::PyOverflowError::new_err(
                    "Data or associated data too long. Max 2**31 - 1 bytes",
                ));
            }
            Ok(())
        };
        let bytes = if let Ok(bytes) = pyobj.cast::<PyBytes>() {
            check_length(bytes.as_bytes().len())?;
            bytes.to_owned()
        } else {
            // Validate the export's byte count before copying a potentially huge
            // mapping. Readonly views can still have mutable underlying storage.
            let view = memory_view(&pyobj, false)?;
            check_length(view.getattr("nbytes")?.extract()?)?;
            view.call_method0("tobytes")?.cast_into::<PyBytes>()?
        };
        Ok(Self {
            pyobj: pyobj.to_owned().unbind(),
            input: Input::Python(bytes.into()),
        })
    }
}
impl<'p> pyo3::conversion::FromPyObject<'_, 'p> for CffiBuf<'p> {
    type Error = pyo3::PyErr;
    fn extract(pyobj: pyo3::Borrowed<'_, 'p, pyo3::PyAny>) -> pyo3::PyResult<Self> {
        Self::extract_limited(pyobj, usize::MAX)
    }
}

/// AEAD's native signed-length limit is checked before any mutable input copy.
pub(crate) fn extract_aead_buffer<'p>(
    obj: &pyo3::Bound<'p, pyo3::PyAny>,
) -> pyo3::PyResult<CffiBuf<'p>> {
    CffiBuf::extract_limited(obj.as_borrowed(), i32::MAX as usize)
}
pub(crate) fn extract_optional_aead_buffer<'p>(
    obj: &pyo3::Bound<'p, pyo3::PyAny>,
) -> pyo3::PyResult<Option<CffiBuf<'p>>> {
    if obj.is_none() {
        Ok(None)
    } else {
        extract_aead_buffer(obj).map(Some)
    }
}

enum Output<'p> {
    Borrowed(&'p mut [u8]),
    Python {
        view: pyo3::Bound<'p, pyo3::PyAny>,
        bytes: SecretBytes,
    },
}

pub(crate) struct CffiMutBuf<'p> {
    output: Output<'p>,
}
impl<'p> CffiMutBuf<'p> {
    pub(crate) fn from_bytes(_py: pyo3::Python<'p>, bytes: &'p mut [u8]) -> Self {
        Self {
            output: Output::Borrowed(bytes),
        }
    }
    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8] {
        match &mut self.output {
            Output::Borrowed(bytes) => bytes,
            Output::Python { bytes, .. } => bytes.as_mut(),
        }
    }
    /// Publish only bytes successfully produced by the operation. Callers use
    /// this after success, including authentication for one-shot AEAD. Failure
    /// leaves the Python destination unchanged and drops the erased staging area.
    pub(crate) fn commit(&self, py: pyo3::Python<'_>, count: usize) -> pyo3::PyResult<()> {
        match &self.output {
            Output::Borrowed(bytes) => {
                if count > bytes.len() {
                    return Err(pyo3::exceptions::PyRuntimeError::new_err(
                        "invalid output length",
                    ));
                }
            }
            Output::Python { view, bytes } => {
                let result = bytes.as_ref().get(..count).ok_or_else(|| {
                    pyo3::exceptions::PyRuntimeError::new_err("invalid output length")
                })?;
                // The memoryview retains the export, preventing resize. No Rust
                // reference ever points at its storage. Tail bytes are untouched.
                view.set_item(
                    PySlice::new(py, 0, count as isize, 1),
                    PyBytes::new(py, result),
                )?;
            }
        }
        Ok(())
    }
}
impl<'p> pyo3::conversion::FromPyObject<'_, 'p> for CffiMutBuf<'p> {
    type Error = pyo3::PyErr;
    fn extract(pyobj: pyo3::Borrowed<'_, 'p, pyo3::PyAny>) -> pyo3::PyResult<Self> {
        let view = memory_view(&pyobj, true)?.call_method1("cast", ("B",))?;
        let bytes = SecretBytes::from(vec![0; view.len()?]);
        Ok(Self {
            output: Output::Python { view, bytes },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::{PyByteArray, PyByteArrayMethods};

    #[test]
    fn output_lengths_cannot_overflow_or_publish_past_capacity() {
        assert_eq!(checked_add_length(usize::MAX - 1, 1).unwrap(), usize::MAX);
        assert!(checked_add_length(usize::MAX, 1).is_err());
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| {
            let mut bytes = [0x42; 4];
            assert!(CffiMutBuf::from_bytes(py, &mut bytes)
                .commit(py, 5)
                .is_err());
            assert_eq!(bytes, [0x42; 4]);
            let original = PyByteArray::new(py, b"keep");
            let mut output = original.extract::<CffiMutBuf<'_>>().unwrap();
            output.as_mut_bytes().fill(0);
            assert!(output.commit(py, 5).is_err());
            assert_eq!(original.to_vec(), b"keep");
        });
    }

    #[test]
    fn mutable_and_readonly_views_are_snapshotted() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| -> pyo3::PyResult<()> {
            let original = PyByteArray::new(py, b"abc");
            let direct = original.extract::<CffiBuf<'_>>()?;
            let view = PyMemoryView::from(original.as_any())?.call_method0("toreadonly")?;
            let readonly = view.extract::<CffiBuf<'_>>()?;
            original.set_item(0, b'z')?;
            assert_eq!(direct.as_bytes(), b"abc");
            assert_eq!(readonly.as_bytes(), b"abc");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn output_is_private_until_commit_and_can_overlap_input() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| -> pyo3::PyResult<()> {
            let original = PyByteArray::new(py, b"abcdef");
            let input = original.extract::<CffiBuf<'_>>()?;
            let mut output = original.extract::<CffiMutBuf<'_>>()?;
            output.as_mut_bytes()[..3].copy_from_slice(b"xyz");
            assert_eq!(original.to_vec(), b"abcdef");
            output.commit(py, 3)?;
            assert_eq!(original.to_vec(), b"xyzdef");
            assert_eq!(input.as_bytes(), b"abcdef");
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn abandoning_output_does_not_publish_partial_results() {
        pyo3::Python::initialize();
        pyo3::Python::attach(|py| -> pyo3::PyResult<()> {
            let original = PyByteArray::new(py, b"sentinel");
            {
                let mut output = original.extract::<CffiMutBuf<'_>>()?;
                output.as_mut_bytes().fill(42);
            }
            assert_eq!(original.to_vec(), b"sentinel");
            Ok(())
        })
        .unwrap();
    }
}
