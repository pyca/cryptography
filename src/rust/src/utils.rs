// This file is dual licensed under the terms of the Apache License, Version
// 2.0, and the BSD License. See the LICENSE file in the root of this repository
// for complete details.

macro_rules! cstr_from_literal {
    ($str:expr) => {
        std::ffi::CStr::from_bytes_with_nul(concat!($str, "\0").as_bytes()).unwrap()
    };
}

pub(crate) use cstr_from_literal;
