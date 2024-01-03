//! The Tree module contains functions and builders for managing certified
//! [request](crate::HttpRequest) and [response](crate::HttpResponse) pairs in a
//! purpose-build HTTP certification data structure.
//!
//! Certifications are prepared using the [Certification] enum.

mod certification;
pub use certification::*;
