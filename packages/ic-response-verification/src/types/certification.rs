/// Parsed request certification CEL expression parameters.
#[derive(Debug, Eq, PartialEq)]
pub struct RequestCertification {
    /// Request headers to include in certification.
    pub certified_request_headers: Vec<String>,
    /// Request query parameters to include in certification.
    pub certified_query_parameters: Vec<String>,
}

/// Parsed response certification CEL expression parameters. Can either include headers using
/// [ResponseCertification::CertifiedHeaders] or exclude them using
/// [ResponseCertification::HeaderExclusions].
#[derive(Debug, Eq, PartialEq)]
pub enum ResponseCertification {
    /// Response headers to exclude from certification.
    HeaderExclusions(Vec<String>),
    /// Response headers to include in certification.
    CertifiedHeaders(Vec<String>),
}

/// Parsed request/response pair certification CEL expression.
#[derive(Debug, Eq, PartialEq)]
pub struct Certification {
    /// Optional rust representation of the request certification CEL expression parameters.
    pub request_certification: Option<RequestCertification>,
    /// Rust representation of the response certification CEL expression parameters.
    pub response_certification: ResponseCertification,
}
