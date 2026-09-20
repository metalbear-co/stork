//! Integration-test facade over the shared harness. The harness is included
//! verbatim; it also serves the crate's `#[cfg(test)]` modules.
#![allow(dead_code)]

include!("../../test-support/harness.rs");
