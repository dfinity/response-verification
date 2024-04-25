//! Utilities for calculating
//! [Representation Independent Hashes](https://internetcomputer.org/docs/current/references/ic-interface-spec/#hash-of-map)
//! of [HttpRequest](crate::HttpRequest) and [HttpResponse](crate::HttpRequest) objects.

mod request_hash;
pub use request_hash::*;

mod response_hash;
pub use response_hash::*;

/// Sha256 Digest: 32 bytes
pub type Hash = [u8; 32];
