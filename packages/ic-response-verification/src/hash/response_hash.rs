use crate::hash::hash;
use crate::hash::representation_independent_hash::{representation_independent_hash, Value};
use crate::types::{Response, ResponseCertification};

const CERTIFICATE_HEADER_NAME: &str = "IC-Certificate";
const CERTIFICATE_EXPRESSION_HEADER_NAME: &str = "IC-Certificate-Expression";
const RESPONSE_STATUS_PSEUDO_HEADER_NAME: &str = ":ic-cert-status";

pub fn response_headers_hash(
    response: &Response,
    response_certification: &ResponseCertification,
) -> [u8; 32] {
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

    let mut filtered_headers: Vec<(String, Value)> = response
        .headers
        .iter()
        .filter_map(|(header_name, header_value)| {
            let is_certificate_header = header_name
                .to_string()
                .eq_ignore_ascii_case(CERTIFICATE_HEADER_NAME);
            if is_certificate_header {
                return None;
            }

            let is_certificate_expression_header = header_name
                .to_string()
                .eq_ignore_ascii_case(CERTIFICATE_EXPRESSION_HEADER_NAME);

            if headers_filter(header_name) || is_certificate_expression_header {
                return Some((
                    header_name.to_string().to_ascii_lowercase(),
                    Value::String(String::from(header_value)),
                ));
            }

            None
        })
        .collect();

    filtered_headers.push((
        RESPONSE_STATUS_PSEUDO_HEADER_NAME.into(),
        Value::Number(response.status_code.into()),
    ));

    representation_independent_hash(&filtered_headers)
}

pub fn response_hash(
    response: &Response,
    response_certification: &ResponseCertification,
) -> [u8; 32] {
    let concatenated_hashes = [
        response_headers_hash(response, response_certification),
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
    fn response_hash_with_certified_headers() {
        let response_certification = ResponseCertification::CertifiedHeaders(vec![
            "Accept-Encoding".into(),
            "Cache-Control".into(),
        ]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let expected_hash =
            hex::decode("f3f918d36368b615b6e2c01a80e9ca95193d09d039b95977c9741579b09f1725")
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
                    "IC-Certificate-Expression".into(),
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
            hex::decode("592bdfe001adca2d48f0372a2d6bbdc561a6806719710dc8d393f8f89f14a25b")
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
                    "IC-Certificate-Expression".into(),
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
            hex::decode("9f90f9e9cc067e1071d4a5e1de415bc261d536a50772fbad2440ccc8494470c2")
                .unwrap();

        let result = response_headers_hash(&response, &response_certification);

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
                    "IC-Certificate-Expression".into(),
                    remove_whitespace(CERTIFIED_HEADERS_CEL_EXPRESSION),
                ),
                ("Accept-Encoding".into(), "gzip".into()),
            ],
            body: HELLO_WORLD_BODY.into(),
        };

        let result = response_headers_hash(&response, &response_certification);
        let result_without_excluded_headers =
            response_headers_hash(&response_without_excluded_headers, &response_certification);

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
            hex::decode("80d1666b9b5f377fafc98ac68e4a9b5514956995937a54e0b50e63b21d9c5bfa")
                .unwrap();

        let result = response_headers_hash(&response, &response_certification);

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
                    "IC-Certificate-Expression".into(),
                    remove_whitespace(HEADER_EXCLUSIONS_CEL_EXPRESSION),
                ),
                ("Accept-Encoding".into(), "gzip".into()),
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
            body: HELLO_WORLD_BODY.into(),
        };

        let result = response_headers_hash(&response, &response_certification);
        let result_without_excluded_headers =
            response_headers_hash(&response_without_excluded_headers, &response_certification);

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
                    "IC-Certificate-Expression".into(),
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
