use crate::HeaderField;
use candid::{CandidType, Deserialize};

/// A Candid-encodable representation of an HTTP response.
/// This struct is used by canisters that implement the HTTP interface required by the HTTP Gateway Protocol.
#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP response status code.
    pub status_code: u16,
    /// HTTP response headers.
    pub headers: Vec<HeaderField>,
    /// Response body as an array of bytes.
    pub body: Vec<u8>,
    /// Whether the request should be upgraded to an update call.
    pub upgrade: Option<bool>,
}
