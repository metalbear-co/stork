//! Bounded PE decoding and local byte transformations.
//!
//! Header parsing and payload checks live in `headers`, managed PE32 widening
//! in `convert`, and import serialization in `imports`. These modules never
//! access a process; strategies own allocation and transactional remote writes.

mod convert;
mod headers;
mod imports;
mod layout;

pub(crate) use convert::convert_pe32_to_pe64;
pub(crate) use headers::{DataDirectory, Headers};
pub(crate) use imports::{ImportDescriptor, MAX_IMPORTS, build_imports};
#[cfg(test)]
use layout::u16_at;
pub(crate) use layout::{
    DOS_HEADER_SIZE, HEADER_PREFIX_SIZE, header_read_size, machine_gate, nt_offset, u32_at,
};

#[cfg(test)]
mod tests;
