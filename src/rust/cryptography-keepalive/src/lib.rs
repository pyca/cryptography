// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

#![deny(rust_2018_idioms, clippy::undocumented_unsafe_blocks)]

use std::cell::UnsafeCell;
use std::ops::Deref;

use pyo3::pybacked::{PyBackedBytes, PyBackedStr};

pub struct KeepAlive<T: StableDeref> {
    values: UnsafeCell<Vec<T>>,
}

/// # Safety
/// Implementers of this trait must ensure that the value returned by
/// `deref()` must remain valid, even if `self` is moved.
pub unsafe trait StableDeref: Deref {}
// SAFETY: `Vec`'s data is on the heap, so as long as it's not mutated, the
// slice returned by `deref` remains valid.
unsafe impl<T> StableDeref for Vec<T> {}
// SAFETY: `PyBackedBytes`'s data is on the heap and `bytes` objects in
// Python are immutable.
unsafe impl StableDeref for PyBackedBytes {}
// SAFETY: `PyBackedStr`'s data is on the heap and `str` objects in
// Python are immutable.
unsafe impl StableDeref for PyBackedStr {}

#[allow(clippy::new_without_default)]
impl<T: StableDeref> KeepAlive<T> {
    pub fn new() -> Self {
        KeepAlive {
            values: UnsafeCell::new(vec![]),
        }
    }

    pub fn add(&self, v: T) -> &T::Target {
        // SAFETY: We only ever append to `self.values`, which, when combined
        // with the invariants of `StableDeref`, means that the result of
        // `deref()` will always be valid for the lifetime of `&self`.
        unsafe {
            let values = &mut *self.values.get();
            values.push(v);
            values.last().unwrap().deref()
        }
    }
}
