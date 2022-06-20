// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

// This file is a backport of `pyo3::intern!` from pyo3 0.16.

#[macro_export]
macro_rules! intern {
    ($py: expr, $text: expr) => {{
        static INTERNED: $crate::intern::Interned = $crate::intern::Interned::new($text);
        INTERNED.get($py)
    }};
}

#[doc(hidden)]
pub struct Interned(
    &'static str,
    pyo3::once_cell::GILOnceCell<pyo3::Py<pyo3::types::PyString>>,
);

impl Interned {
    pub const fn new(value: &'static str) -> Self {
        Interned(value, pyo3::once_cell::GILOnceCell::new())
    }

    #[inline]
    pub fn get<'py>(&'py self, py: pyo3::Python<'py>) -> &'py pyo3::types::PyString {
        self.1
            .get_or_init(py, || pyo3::types::PyString::new(py, self.0).into())
            .as_ref(py)
    }
}

#[cfg(test)]
mod tests {
    use super::Interned;

    #[test]
    fn test_interned_new() {
        for s in ["abc", "123"] {
            Interned::new(s);
        }
    }
}
