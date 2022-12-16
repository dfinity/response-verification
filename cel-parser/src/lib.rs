#![allow(dead_code, unused_variables, unused_imports, unused_imports)]

mod mock;
use mock::*;

struct RequestCertification {
    certified_request_headers: Vec<String>,
    certified_query_parameters: Vec<String>,
}

enum ResponseCertification {
    HeaderExclusions(Vec<String>),
    CertifiedHeaders(Vec<String>),
}

struct Certification {
    request_certification: Option<RequestCertification>,
    response_certification: ResponseCertification,
}

impl Certification {
    fn new() -> Self {
        Certification {
            request_certification: None,
            response_certification: ResponseCertification::HeaderExclusions(vec![]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
