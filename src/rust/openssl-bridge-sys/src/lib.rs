//! Header-generated bindings. Every foreign call requires an explicit safety proof.
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
// Bindgen emits these patterns for C bitfields. Keep the exceptions confined
// to generated declarations; the handwritten safe crate uses strict Clippy.
#![allow(
    clippy::missing_safety_doc,
    clippy::ptr_offset_with_cast,
    clippy::useless_transmute
)]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
