//! The utils module contains utility functions used internally by this library.
//! They are exported for use in other libraries that depend on this one, or for
//! advanced use cases that require custom logic.

mod wildcard_paths;
pub use wildcard_paths::*;
