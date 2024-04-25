//! The Tree module contains functions and builders for managing certified
//! [HttpRequest](crate::HttpRequest) and [HttpResponse](crate::HttpResponse) pairs in a
//! purpose-build HTTP certification data structure.
//!
//! Certifications are prepared using the [HttpCertification] enum.

mod certification;
mod certification_tree;
mod certification_tree_entry;
mod certification_tree_path;

pub use certification::*;
pub use certification_tree::*;
pub use certification_tree_entry::*;
pub use certification_tree_path::*;
