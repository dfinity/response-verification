//! # Response Verification

#![deny(missing_docs, missing_debug_implementations, rustdoc::all, clippy::all)]

mod verification;
pub use verification::*;
mod error;
pub use error::*;

pub mod cel;
pub mod types;

mod base64;
mod validation;

#[cfg(test)]
mod test_utils;
