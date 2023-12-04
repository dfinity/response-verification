//! The error module contains types for common errors that may be thrown
//! by other modules in this crate.

/// HTTP certification result type.
pub type HttpCertificationResult<T = ()> = Result<T, HttpCertificationError>;

/// HTTP certification error type.
#[derive(thiserror::Error, Debug)]
pub enum HttpCertificationError {
    /// The URL was malformed and could not be parsed correctly.
    #[error(r#"Failed to parse url: "{0}""#)]
    MalformedUrl(String),

    /// Error converting UTF-8 string.
    #[error(r#"Error converting UTF8 string bytes: "{0}""#)]
    Utf8ConversionError(#[from] std::string::FromUtf8Error),
}
