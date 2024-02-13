//! The error module contains types for common errors that may be thrown
//! by other modules in this crate.

use ic_http_certification::HttpCertificationError;

/// HTTP certification result type.
pub type AssetCertificationResult<T = ()> = Result<T, AssetCertificationError>;

/// HTTP certification error type.
#[derive(thiserror::Error, Debug)]
pub enum AssetCertificationError {
    /// Error converting UTF-8 string.
    #[error(r#"Error converting UTF8 string bytes: "{0}""#)]
    HttpCertificationError(#[from] HttpCertificationError),
}
