//! The HTTP module contains types for representing HTTP requests and responses in Rust.
//! These types are Candid-encodable and are used by canisters that implement the
//! HTTP interface required by the HTTP Gateway Protocol.

mod header_field;
mod http_request;
mod http_response;

pub use header_field::*;
pub use http_request::*;
pub use http_response::*;
