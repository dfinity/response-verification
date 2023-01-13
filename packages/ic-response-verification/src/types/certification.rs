#[derive(Debug, Eq, PartialEq)]
pub struct RequestCertification {
    pub certified_request_headers: Vec<String>,
    pub certified_query_parameters: Vec<String>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum ResponseCertification {
    HeaderExclusions(Vec<String>),
    CertifiedHeaders(Vec<String>),
}

#[derive(Debug, Eq, PartialEq)]
pub struct Certification {
    pub request_certification: Option<RequestCertification>,
    pub response_certification: ResponseCertification,
}
