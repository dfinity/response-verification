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

    /// Error converting bytes to string.
    #[error(r#"Wildcard path "{wildcard_path}" is too specific for request path "{request_path}", use a less specific wildcard path"#)]
    WildcardPathNotValidForRequestPath {
        /// The wildcard path that was not valid for the request path.
        wildcard_path: String,

        /// The request path that was not valid for the wildcard path.
        request_path: String,
    },

    /// The `IC-CertificateExpression` header in a response did not match the Cel expression used to certify the [HttpResponse](crate::HttpResponse).
    #[error(r#"The IC-CertificateExpression header in the response did not match the Cel expression used to certify the response. Expected: "{expected}", Actual: "{actual}""#)]
    CertificateExpressionHeaderMismatch {
        /// The expected value of the `IC-CertificateExpression` header. This is the Cel expression used to certify the [HttpResponse](crate::HttpResponse).
        expected: String,

        /// The actual value of the `IC-CertificateExpression` header.
        actual: String,
    },

    /// The `IC-CertificateExpression header` was missing from the [HttpResponse](crate::HttpResponse).
    #[error(r#"The IC-CertificateExpression header was missing from the response. Expected: "{expected}""#)]
    CertificateExpressionHeaderMissing {
        /// The expected value of the `IC-CertificateExpression` header. This is the Cel expression used to certify the [HttpResponse](crate::HttpResponse).
        expected: String,
    },

    /// The `IC-CertificateExpression` header in a response contained multiple values.
    #[error(r#"The IC-CertificateExpression header in the response contained multiple values. Expected only one: "{expected}""#)]
    MultipleCertificateExpressionHeaders {
        /// The expected value of the `IC-CertificateExpression` header. This is the Cel expression used to certify the [HttpResponse](crate::HttpResponse).
        expected: String,
    },
}
