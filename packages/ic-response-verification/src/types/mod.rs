//! Public types used for response verification.

/// Types to represent the result of verifying a request/response pair's certification.
mod verification_result;
pub use verification_result::*;

/// Types to represent a certified response that clients can use to determine which parts of a response are safe to use.
mod verified_response;
pub use verified_response::*;
