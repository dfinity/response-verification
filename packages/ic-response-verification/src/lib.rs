//! # Response Verification

#![deny(
    missing_docs,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]

mod verification;
pub use verification::*;
mod error;
pub use error::*;

pub mod cel;
pub mod hash;
pub mod types;

mod base64;
mod test_utils;
mod validation;
