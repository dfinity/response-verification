use crate::types::{Response, ResponseCertification};
use ic_certification::hash_tree::Sha256Digest;
use ic_representation_independent_hash::{hash, representation_independent_hash, Value};

const CERTIFICATE_HEADER_NAME: &str = "IC-Certificate";
const CERTIFICATE_EXPRESSION_HEADER_NAME: &str = "IC-CertificateExpression";
const RESPONSE_STATUS_PSEUDO_HEADER_NAME: &str = ":ic-cert-status";

/// Representation of response headers filtered by [filter_response_headers].
#[derive(Debug)]
pub struct ResponseHeaders {
    /// Filtered headers
    pub headers: Vec<(String, String)>,
    /// IC-Certificate header
    pub certificate: Option<String>,
    /// IC-CertificateExpression header
    pub certificate_expression: Option<String>,
}

/// Filters headers of [crate::types::Response] according to [crate::types::ResponseCertification]
/// returned from [crate::cel::cel_to_certification].
pub fn filter_response_headers(
    response: &Response,
    response_certification: &ResponseCertification,
) -> ResponseHeaders {
    let headers_filter: Box<dyn Fn(_) -> _> = match response_certification {
        ResponseCertification::CertifiedHeaders(headers_to_include) => {
            Box::new(move |header_name: &String| {
                headers_to_include.iter().any(|header_to_include| {
                    header_to_include.eq_ignore_ascii_case(&header_name.to_string())
                })
            })
        }
        ResponseCertification::HeaderExclusions(headers_to_exclude) => {
            Box::new(move |header_name: &String| {
                !headers_to_exclude.iter().any(|header_to_exclude| {
                    header_to_exclude.eq_ignore_ascii_case(&header_name.to_string())
                })
            })
        }
    };

    let mut response_headers = ResponseHeaders {
        headers: vec![],
        certificate: None,
        certificate_expression: None,
    };

    response_headers.headers = response
        .headers
        .iter()
        .filter_map(|(header_name, header_value)| {
            let is_certificate_header = header_name
                .to_string()
                .eq_ignore_ascii_case(CERTIFICATE_HEADER_NAME);
            if is_certificate_header {
                response_headers.certificate = Some(header_value.into());
                return None;
            }

            let is_certificate_expression_header = header_name
                .to_string()
                .eq_ignore_ascii_case(CERTIFICATE_EXPRESSION_HEADER_NAME);
            if is_certificate_expression_header {
                response_headers.certificate_expression = Some(header_value.into());
                return None;
            }

            if headers_filter(header_name) {
                return Some((
                    header_name.to_string().to_ascii_lowercase(),
                    String::from(header_value),
                ));
            }

            None
        })
        .collect();

    response_headers
}

/// Calculates the
/// [Representation Independent Hash](https://internetcomputer.org/docs/current/references/ic-interface-spec/#hash-of-map)
/// of [ResponseHeaders] that have been filtered with [filter_response_headers].
pub fn response_headers_hash(
    status_code: &u64,
    response_headers: &ResponseHeaders,
) -> Sha256Digest {
    let mut headers_to_verify: Vec<(String, Value)> = response_headers
        .headers
        .iter()
        .map(|(header_name, header_value)| {
            (
                header_name.to_string(),
                Value::String(String::from(header_value)),
            )
        })
        .collect();

    if let Some(certificate_expression) = &response_headers.certificate_expression {
        headers_to_verify.push((
            CERTIFICATE_EXPRESSION_HEADER_NAME.to_ascii_lowercase(),
            Value::String(certificate_expression.clone()),
        ));
    }

    headers_to_verify.push((
        RESPONSE_STATUS_PSEUDO_HEADER_NAME.into(),
        Value::Number(*status_code),
    ));

    representation_independent_hash(&headers_to_verify)
}
/// Calculates the
/// [Representation Independent Hash](https://internetcomputer.org/docs/current/references/ic-interface-spec/#hash-of-map)
/// of a [crate::types::Response] according to [crate::types::ResponseCertification] returned from
/// [crate::cel::cel_to_certification].
pub fn response_hash(
    response: &Response,
    response_certification: &ResponseCertification,
) -> Sha256Digest {
    // lower case the headers here
    let filtered_headers = filter_response_headers(response, response_certification);
    let concatenated_hashes = [
        response_headers_hash(&response.status_code.into(), &filtered_headers),
        hash(&response.body),
    ]
    .concat();

    hash(concatenated_hashes.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_utils::remove_whitespace;

    const HELLO_WORLD_BODY: &[u8] = &[72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100, 33];
    const CERTIFICATE: &str = "certificate=:SGVsbG8gQ2VydGlmaWNhdGUh:,tree=:SGVsbG8gVHJlZSE=:";
    const HEADER_EXCLUSIONS_CEL_EXPRESSION: &str = r#"
        default_certification (
          ValidationArgs {
            certification: Certification {
              no_request_certification: Empty {},
              response_certification: ResponseCertification {
                response_header_exclusions: ResponseHeaderList {
                  headers: ["Content-Security-Policy"]
                }
              }
            }
          }
        )
    "#;
    const CERTIFIED_HEADERS_CEL_EXPRESSION: &str = r#"
        default_certification (
          ValidationArgs {
            certification: Certification {
              no_request_certification: Empty {},
              response_certification: ResponseCertification {
                certified_response_headers: ResponseHeaderList {
                  headers: ["Accept-Encoding", "Cache-Control"]
                }
              }
            }
          }
        )
    "#;

    #[test]
    fn response_with_certified_headers_without_excluded_headers() {
        let response_certification =
            ResponseCertification::CertifiedHeaders(vec!["Accept-Encoding".into()]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let response_headers = filter_response_headers(&response, &response_certification);

        assert_eq!(
            response_headers.headers,
            vec![("accept-encoding".into(), "gzip".into()),]
        );
    }

    #[test]
    fn response_with_certified_headers() {
        let response_certification = ResponseCertification::CertifiedHeaders(vec![
            "Accept-Encoding".into(),
            "Cache-Control".into(),
        ]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let response_headers = filter_response_headers(&response, &response_certification);

        assert_eq!(
            response_headers.headers,
            vec![
                ("accept-encoding".into(), "gzip".into()),
                ("cache-control".into(), "no-cache".into()),
                ("cache-control".into(), "no-store".into()),
            ]
        );
    }

    #[test]
    fn response_hash_with_certified_headers() {
        let response_certification = ResponseCertification::CertifiedHeaders(vec![
            "Accept-Encoding".into(),
            "Cache-Control".into(),
        ]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let expected_hash =
            hex::decode("3393250e3cedc30408dcb7e8963898c3d7549b8a0b76496b82fdfeae99c2ac78")
                .unwrap();

        let result = response_hash(&response, &response_certification);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn response_hash_with_certified_headers_without_excluded_headers() {
        let response_certification =
            ResponseCertification::CertifiedHeaders(vec!["Accept-Encoding".into()]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let response_without_excluded_headers = Response {
            status_code: 200,
            headers: vec![
                (
                    "IC-CertificateExpression".into(),
                    remove_whitespace(CERTIFIED_HEADERS_CEL_EXPRESSION),
                ),
                ("Accept-Encoding".into(), "gzip".into()),
            ],
            body: HELLO_WORLD_BODY.into(),
        };

        let result = response_hash(&response, &response_certification);
        let result_without_excluded_headers =
            response_hash(&response_without_excluded_headers, &response_certification);

        assert_eq!(result, result_without_excluded_headers);
    }

    #[test]
    fn response_hash_with_header_exclusions() {
        let response_certification = ResponseCertification::HeaderExclusions(vec![
            "Accept-Encoding".into(),
            "Cache-Control".into(),
        ]);
        let response = create_response(HEADER_EXCLUSIONS_CEL_EXPRESSION);
        let expected_hash =
            hex::decode("a2ffb50ef8971650c2fb46c0a2788b7d5ac5a027d635175e8e06b419ce6c4cda")
                .unwrap();

        let result = response_hash(&response, &response_certification);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn response_hash_with_header_exclusions_without_excluded_headers() {
        let response_certification =
            ResponseCertification::HeaderExclusions(vec!["Content-Security-Policy".into()]);
        let response = create_response(HEADER_EXCLUSIONS_CEL_EXPRESSION);
        let response_without_excluded_headers = Response {
            status_code: 200,
            headers: vec![
                (
                    "IC-CertificateExpression".into(),
                    remove_whitespace(HEADER_EXCLUSIONS_CEL_EXPRESSION),
                ),
                ("Accept-Encoding".into(), "gzip".into()),
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: HELLO_WORLD_BODY.into(),
        };

        let result = response_hash(&response, &response_certification);
        let result_without_excluded_headers =
            response_hash(&response_without_excluded_headers, &response_certification);

        assert_eq!(result, result_without_excluded_headers);
    }

    #[test]
    fn response_headers_hash_with_certified_headers() {
        let response_certification = ResponseCertification::CertifiedHeaders(vec![
            "Accept-Encoding".into(),
            "Cache-Control".into(),
        ]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let expected_hash =
            hex::decode("eac859a99d5bd7b71f46dbacecff4aaa0a7a7131802c136a77a76c8e018af5f7")
                .unwrap();

        let filtered_headers = filter_response_headers(&response, &response_certification);
        let result = response_headers_hash(&response.status_code.into(), &filtered_headers);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn response_headers_hash_with_certified_headers_without_excluded_headers() {
        let response_certification =
            ResponseCertification::CertifiedHeaders(vec!["Accept-Encoding".into()]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let response_without_excluded_headers = Response {
            status_code: 200,
            headers: vec![
                ("IC-Certificate".into(), CERTIFICATE.into()),
                (
                    "IC-CertificateExpression".into(),
                    remove_whitespace(CERTIFIED_HEADERS_CEL_EXPRESSION),
                ),
                ("Accept-Encoding".into(), "gzip".into()),
            ],
            body: HELLO_WORLD_BODY.into(),
        };

        let filtered_headers = filter_response_headers(&response, &response_certification);
        let result = response_headers_hash(&response.status_code.into(), &filtered_headers);
        let filtered_headers_without_excluded_headers =
            filter_response_headers(&response_without_excluded_headers, &response_certification);
        let result_without_excluded_headers = response_headers_hash(
            &response_without_excluded_headers.status_code.into(),
            &filtered_headers_without_excluded_headers,
        );

        assert_eq!(result, result_without_excluded_headers);
    }

    #[test]
    fn response_headers_hash_with_header_exclusions() {
        let response_certification = ResponseCertification::HeaderExclusions(vec![
            "Accept-Encoding".into(),
            "Cache-Control".into(),
        ]);
        let response = create_response(HEADER_EXCLUSIONS_CEL_EXPRESSION);
        let expected_hash =
            hex::decode("d618f70bf2578d5a672374ffbaade3910e858384f42d01ac2863946ab596bcac")
                .unwrap();

        let filtered_headers = filter_response_headers(&response, &response_certification);
        let result = response_headers_hash(&response.status_code.into(), &filtered_headers);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn response_headers_hash_with_header_exclusions_without_excluded_headers() {
        let response_certification =
            ResponseCertification::HeaderExclusions(vec!["Content-Security-Policy".into()]);
        let response = create_response(HEADER_EXCLUSIONS_CEL_EXPRESSION);
        let response_without_excluded_headers = Response {
            status_code: 200,
            headers: vec![
                ("IC-Certificate".into(), CERTIFICATE.into()),
                (
                    "IC-CertificateExpression".into(),
                    remove_whitespace(HEADER_EXCLUSIONS_CEL_EXPRESSION),
                ),
                ("Accept-Encoding".into(), "gzip".into()),
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: HELLO_WORLD_BODY.into(),
        };

        let filtered_headers = filter_response_headers(&response, &response_certification);
        let result = response_headers_hash(&response.status_code.into(), &filtered_headers);

        let response_headers_without_excluded_headers =
            filter_response_headers(&response_without_excluded_headers, &response_certification);
        let result_without_excluded_headers = response_headers_hash(
            &response_without_excluded_headers.status_code.into(),
            &response_headers_without_excluded_headers,
        );

        assert_eq!(result, result_without_excluded_headers);
    }

    /// We remove white space from CEL expressions to ease the calculation
    /// of the expected hashes. Generating the hash for a string with so much whitespace manually
    /// may be prone to error in copy/pasting the string into a website and missing a leading/trailing
    /// newline or a tab character somewhere.
    fn create_response(cel_expression: &str) -> Response {
        Response {
            status_code: 200,
            headers: vec![
                ("IC-Certificate".into(), CERTIFICATE.into()),
                (
                    "IC-CertificateExpression".into(),
                    remove_whitespace(cel_expression),
                ),
                ("Accept-Encoding".into(), "gzip".into()),
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
                (
                    "Content-Security-Policy".into(),
                    "default-src 'self'".into(),
                ),
            ],
            body: HELLO_WORLD_BODY.into(),
        }
    }
}
