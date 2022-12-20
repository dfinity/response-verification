pub struct RequestCertification {
    pub certified_request_headers: Vec<String>,
    pub certified_query_parameters: Vec<String>,
}

pub enum ResponseCertification {
    HeaderExclusions(Vec<String>),
    CertifiedHeaders(Vec<String>),
}

pub struct Certification {
    pub request_certification: Option<RequestCertification>,
    pub response_certification: ResponseCertification,
}

impl Certification {
    fn new() -> Self {
        Certification {
            request_certification: None,
            response_certification: ResponseCertification::HeaderExclusions(vec![]),
        }
    }
}
