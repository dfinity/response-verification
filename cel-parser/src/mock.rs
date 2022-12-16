#![allow(dead_code, unused_variables, unused_imports, unused_imports)]

use crate::{Certification, RequestCertification, ResponseCertification};

// just to be clean, this is *not* HttpRequest::certificate_version
enum MockVersion {
    None,
    EmptyV1,
    EmptyV2,
    DataV1,
    DataV2,
    DataV3,
    DataV4,
    DataV5,
    DataV6,
    DataV7,
}

impl Certification {
    fn mock(v: MockVersion) -> Option<Self> {
        match v {
            MockVersion::None => None,
            MockVersion::EmptyV1 => Some(Certification {
                request_certification: None,
                response_certification: ResponseCertification::HeaderExclusions(vec![]),
            }),
            MockVersion::EmptyV2 => Some(Certification {
                request_certification: Some(RequestCertification {
                    certified_request_headers: vec![],
                    certified_query_parameters: vec![],
                }),
                response_certification: ResponseCertification::CertifiedHeaders(vec![]),
            }),
            MockVersion::DataV1 => Some(Certification {
                request_certification: Some(RequestCertification {
                    certified_request_headers: vec!["foo".to_string()],
                    certified_query_parameters: vec!["bar".to_string()],
                }),
                response_certification: ResponseCertification::HeaderExclusions(vec![
                    "baz".to_string()
                ]),
            }),
            MockVersion::DataV2 => Some(Certification {
                request_certification: Some(RequestCertification {
                    certified_request_headers: vec!["foo".to_string()],
                    certified_query_parameters: vec!["bar".to_string()],
                }),
                response_certification: ResponseCertification::HeaderExclusions(vec![]),
            }),
            MockVersion::DataV3 => Some(Certification {
                request_certification: Some(RequestCertification {
                    certified_request_headers: vec!["foo".to_string()],
                    certified_query_parameters: vec![],
                }),
                response_certification: ResponseCertification::CertifiedHeaders(vec![]),
            }),
            MockVersion::DataV4 => Some(Certification {
                request_certification: Some(RequestCertification {
                    certified_request_headers: vec![],
                    certified_query_parameters: vec!["bar".to_string()],
                }),
                response_certification: ResponseCertification::CertifiedHeaders(vec![]),
            }),
            MockVersion::DataV5 => Some(Certification {
                request_certification: Some(RequestCertification {
                    certified_request_headers: vec![],
                    certified_query_parameters: vec!["bar".to_string()],
                }),
                response_certification: ResponseCertification::HeaderExclusions(vec![
                    "baz".to_string()
                ]),
            }),
            MockVersion::DataV6 => Some(Certification {
                request_certification: Some(RequestCertification {
                    certified_request_headers: vec!["foo".to_string()],
                    certified_query_parameters: vec![],
                }),
                response_certification: ResponseCertification::HeaderExclusions(vec![
                    "baz".to_string()
                ]),
            }),
            MockVersion::DataV7 => Some(Certification {
                request_certification: Some(RequestCertification {
                    certified_request_headers: vec![],
                    certified_query_parameters: vec![],
                }),
                response_certification: ResponseCertification::HeaderExclusions(vec![
                    "baz".to_string()
                ]),
            }),
        }
    }
}
