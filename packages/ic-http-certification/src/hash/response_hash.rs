use super::Hash;
use crate::{cel::DefaultResponseCertificationType, DefaultResponseCertification, HttpResponse};
use ic_representation_independent_hash::{hash, representation_independent_hash, Value};

/// The name of the IC-Certificate header.
pub const CERTIFICATE_HEADER_NAME: &str = "IC-Certificate";

/// The name of the IC-CertificateExpression header.
pub const CERTIFICATE_EXPRESSION_HEADER_NAME: &str = "IC-CertificateExpression";

/// The pseudo-header name used for encoding the response status code in the
/// [Representation Independent Hash](https://internetcomputer.org/docs/references/ic-interface-spec/#hash-of-map).
pub const RESPONSE_STATUS_PSEUDO_HEADER_NAME: &str = ":ic-cert-status";

/// Representation of response headers filtered by [filter_response_headers].
#[derive(Debug)]
pub struct ResponseHeaders {
    /// Filtered headers
    pub headers: Vec<(String, String)>,
    /// IC-Certificate header
    pub certificate: Option<String>,
}

/// Filters the headers of an [HttpResponse] according to a CEL expression defined by
/// [DefaultResponseCertification].
pub fn filter_response_headers(
    response: &HttpResponse,
    response_certification: &DefaultResponseCertification<'_>,
) -> ResponseHeaders {
    let headers_filter: Box<dyn Fn(_) -> _> = match response_certification.get_type() {
        DefaultResponseCertificationType::CertifiedResponseHeaders(headers_to_include) => {
            Box::new(move |header_name: &String| {
                headers_to_include.iter().any(|header_to_include| {
                    header_to_include.eq_ignore_ascii_case(&header_name.to_string())
                })
            })
        }
        DefaultResponseCertificationType::ResponseHeaderExclusions(headers_to_exclude) => {
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
    };

    response_headers.headers = response
        .headers()
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
                return Some((
                    header_name.to_string().to_ascii_lowercase(),
                    String::from(header_value),
                ));
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
/// [Representation Independent Hash](https://internetcomputer.org/docs/references/ic-interface-spec/#hash-of-map)
/// of [ResponseHeaders] that have been filtered with [filter_response_headers].
pub fn response_headers_hash(status_code: &u64, response_headers: &ResponseHeaders) -> Hash {
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

    headers_to_verify.push((
        RESPONSE_STATUS_PSEUDO_HEADER_NAME.into(),
        Value::Number(*status_code),
    ));

    representation_independent_hash(&headers_to_verify)
}

/// Computes the v2 response hash from pre-built header pairs, a status code, and a body hash.
///
/// This is a lower-level variant of [`response_hash`] that operates on headers already
/// represented as `(String, Value)` pairs (the format used by
/// [`representation_independent_hash`]). It appends the `:ic-cert-status` pseudo-header
/// internally.
///
/// The result is `SHA-256(header_hash || body_hash)` where `header_hash` is the
/// representation-independent hash of the headers including the status pseudo-header.
///
/// # Expected input shape
///
/// To produce a hash that matches [`response_hash`], `certified_headers` must follow the
/// same normalization that [`filter_response_headers`] applies:
///
/// - Header names must be ASCII-lowercased.
/// - The `IC-Certificate` header must be excluded.
/// - The `IC-CertificateExpression` header must be included (if present on the response).
/// - The CEL `DefaultResponseCertification` filter (certified list or exclusion list)
///   must already have been applied.
/// - Values must be [`Value::String`] (no other [`Value`] variants are produced by
///   [`response_headers_hash`] for header entries).
///
/// Callers that start from an [`HttpResponse`] and a [`DefaultResponseCertification`]
/// should prefer [`response_hash`], which performs all of the above.
///
/// # Panics (debug builds)
///
/// Debug-asserts that `certified_headers` does not already contain
/// [`RESPONSE_STATUS_PSEUDO_HEADER_NAME`]. Passing it would produce duplicate keys
/// and a hash that does not match [`response_hash`]. In release builds this check is
/// skipped; callers must uphold the precondition themselves.
pub fn response_hash_from_headers(
    certified_headers: &[(String, Value)],
    status_code: u16,
    body_hash: &Hash,
) -> Hash {
    debug_assert!(
        !certified_headers
            .iter()
            .any(|(k, _)| k == RESPONSE_STATUS_PSEUDO_HEADER_NAME),
        "certified_headers must not contain the status pseudo-header; it is added internally"
    );
    let mut headers = Vec::with_capacity(certified_headers.len() + 1);
    headers.extend_from_slice(certified_headers);
    headers.push((
        RESPONSE_STATUS_PSEUDO_HEADER_NAME.into(),
        Value::Number(status_code.into()),
    ));
    let header_hash = representation_independent_hash(&headers);
    hash(
        [header_hash.as_ref(), body_hash.as_ref()]
            .concat()
            .as_slice(),
    )
}

/// Calculates the
/// [Representation Independent Hash](https://internetcomputer.org/docs/references/ic-interface-spec/#hash-of-map)
/// of an [HttpResponse] according to a CEL expression defined by [DefaultResponseCertification].
///
/// An optional response body hash may be provided if this is known beforehand. If this override is not
/// provided then the response body hash will be calculated by this function.
pub fn response_hash(
    response: &HttpResponse,
    response_certification: &DefaultResponseCertification,
    response_body_hash: Option<Hash>,
) -> Hash {
    let response_body_hash = response_body_hash.unwrap_or_else(|| hash(response.body()));

    let filtered_headers = filter_response_headers(response, response_certification);
    let concatenated_hashes = [
        response_headers_hash(&response.status_code().as_u16().into(), &filtered_headers),
        response_body_hash,
    ]
    .concat();

    hash(concatenated_hashes.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

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
            DefaultResponseCertification::certified_response_headers(vec!["Accept-Encoding"]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let response_headers = filter_response_headers(&response, &response_certification);

        assert_eq!(
            response_headers.headers,
            vec![
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.to_lowercase(),
                    remove_whitespace(CERTIFIED_HEADERS_CEL_EXPRESSION),
                ),
                ("accept-encoding".into(), "gzip".into()),
            ]
        );
    }

    #[test]
    fn response_with_certified_headers() {
        let response_certification =
            DefaultResponseCertification::certified_response_headers(vec![
                "Accept-Encoding",
                "Cache-Control",
            ]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let response_headers = filter_response_headers(&response, &response_certification);

        assert_eq!(
            response_headers.headers,
            vec![
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.to_lowercase(),
                    remove_whitespace(CERTIFIED_HEADERS_CEL_EXPRESSION),
                ),
                ("accept-encoding".into(), "gzip".into()),
                ("cache-control".into(), "no-cache".into()),
                ("cache-control".into(), "no-store".into()),
            ]
        );
    }

    #[test]
    fn response_hash_with_certified_headers() {
        let response_certification =
            DefaultResponseCertification::certified_response_headers(vec![
                "Accept-Encoding",
                "Cache-Control",
            ]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let expected_hash =
            hex::decode("3393250e3cedc30408dcb7e8963898c3d7549b8a0b76496b82fdfeae99c2ac78")
                .unwrap();

        let result = response_hash(&response, &response_certification, None);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn response_hash_with_certified_headers_without_excluded_headers() {
        let response_certification =
            DefaultResponseCertification::certified_response_headers(vec!["Accept-Encoding"]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let response_without_excluded_headers = HttpResponse::ok(
            HELLO_WORLD_BODY,
            vec![
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.into(),
                    remove_whitespace(CERTIFIED_HEADERS_CEL_EXPRESSION),
                ),
                ("Accept-Encoding".into(), "gzip".into()),
            ],
        )
        .build();

        let result = response_hash(&response, &response_certification, None);
        let result_without_excluded_headers = response_hash(
            &response_without_excluded_headers,
            &response_certification,
            None,
        );

        assert_eq!(result, result_without_excluded_headers);
    }

    #[test]
    fn response_hash_with_header_exclusions() {
        let response_certification =
            DefaultResponseCertification::response_header_exclusions(vec![
                "Accept-Encoding",
                "Cache-Control",
            ]);
        let response = create_response(HEADER_EXCLUSIONS_CEL_EXPRESSION);
        let expected_hash =
            hex::decode("a2ffb50ef8971650c2fb46c0a2788b7d5ac5a027d635175e8e06b419ce6c4cda")
                .unwrap();

        let result = response_hash(&response, &response_certification, None);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn response_hash_with_header_exclusions_without_excluded_headers() {
        let response_certification =
            DefaultResponseCertification::response_header_exclusions(vec![
                "Content-Security-Policy",
            ]);
        let response = create_response(HEADER_EXCLUSIONS_CEL_EXPRESSION);
        let response_without_excluded_headers = HttpResponse::ok(
            HELLO_WORLD_BODY,
            vec![
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.into(),
                    remove_whitespace(HEADER_EXCLUSIONS_CEL_EXPRESSION),
                ),
                ("Accept-Encoding".into(), "gzip".into()),
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
        )
        .build();

        let result = response_hash(&response, &response_certification, None);
        let result_without_excluded_headers = response_hash(
            &response_without_excluded_headers,
            &response_certification,
            None,
        );

        assert_eq!(result, result_without_excluded_headers);
    }

    #[test]
    fn response_headers_hash_with_certified_headers() {
        let response_certification =
            DefaultResponseCertification::certified_response_headers(vec![
                "Accept-Encoding",
                "Cache-Control",
            ]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let expected_hash =
            hex::decode("eac859a99d5bd7b71f46dbacecff4aaa0a7a7131802c136a77a76c8e018af5f7")
                .unwrap();

        let filtered_headers = filter_response_headers(&response, &response_certification);
        let result =
            response_headers_hash(&response.status_code().as_u16().into(), &filtered_headers);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn response_headers_hash_with_certified_headers_without_excluded_headers() {
        let response_certification =
            DefaultResponseCertification::certified_response_headers(vec!["Accept-Encoding"]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let response_without_excluded_headers = HttpResponse::ok(
            HELLO_WORLD_BODY,
            vec![
                (CERTIFICATE_HEADER_NAME.into(), CERTIFICATE.into()),
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.into(),
                    remove_whitespace(CERTIFIED_HEADERS_CEL_EXPRESSION),
                ),
                ("Accept-Encoding".into(), "gzip".into()),
            ],
        )
        .build();

        let filtered_headers = filter_response_headers(&response, &response_certification);
        let result =
            response_headers_hash(&response.status_code().as_u16().into(), &filtered_headers);
        let filtered_headers_without_excluded_headers =
            filter_response_headers(&response_without_excluded_headers, &response_certification);
        let result_without_excluded_headers = response_headers_hash(
            &response_without_excluded_headers
                .status_code()
                .as_u16()
                .into(),
            &filtered_headers_without_excluded_headers,
        );

        assert_eq!(result, result_without_excluded_headers);
    }

    #[test]
    fn response_headers_hash_with_header_exclusions() {
        let response_certification =
            DefaultResponseCertification::response_header_exclusions(vec![
                "Accept-Encoding",
                "Cache-Control",
            ]);
        let response = create_response(HEADER_EXCLUSIONS_CEL_EXPRESSION);
        let expected_hash =
            hex::decode("d618f70bf2578d5a672374ffbaade3910e858384f42d01ac2863946ab596bcac")
                .unwrap();

        let filtered_headers = filter_response_headers(&response, &response_certification);
        let result =
            response_headers_hash(&response.status_code().as_u16().into(), &filtered_headers);

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn response_headers_hash_with_header_exclusions_without_excluded_headers() {
        let response_certification =
            DefaultResponseCertification::response_header_exclusions(vec![
                "Content-Security-Policy",
            ]);
        let response = create_response(HEADER_EXCLUSIONS_CEL_EXPRESSION);
        let response_without_excluded_headers = HttpResponse::ok(
            HELLO_WORLD_BODY,
            vec![
                (CERTIFICATE_HEADER_NAME.into(), CERTIFICATE.into()),
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.into(),
                    remove_whitespace(HEADER_EXCLUSIONS_CEL_EXPRESSION),
                ),
                ("Accept-Encoding".into(), "gzip".into()),
                ("Cache-Control".into(), "no-cache".into()),
                ("Cache-Control".into(), "no-store".into()),
            ],
        )
        .build();

        let filtered_headers = filter_response_headers(&response, &response_certification);
        let result =
            response_headers_hash(&response.status_code().as_u16().into(), &filtered_headers);

        let response_headers_without_excluded_headers =
            filter_response_headers(&response_without_excluded_headers, &response_certification);
        let result_without_excluded_headers = response_headers_hash(
            &response_without_excluded_headers
                .status_code()
                .as_u16()
                .into(),
            &response_headers_without_excluded_headers,
        );

        assert_eq!(result, result_without_excluded_headers);
    }

    #[test]
    fn response_hash_with_body_hash_override() {
        let response_certification =
            DefaultResponseCertification::certified_response_headers(vec![
                "Accept-Encoding",
                "Cache-Control",
            ]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let response_body_hash: Hash =
            hex::decode("5462fc394013080effc31d578ec3fff8b44cdf24738b38a77ce4afacbc93a7f5")
                .unwrap()
                .try_into()
                .unwrap();
        let expected_hash =
            hex::decode("1afc744a377cb8785d1078f53f9bbc9160d86b7a05f490e42c89366326eaef20")
                .unwrap();

        let result = response_hash(&response, &response_certification, Some(response_body_hash));

        assert_eq!(result, expected_hash.as_slice());
    }

    #[test]
    fn response_hash_from_headers_matches_response_hash() {
        let response_certification =
            DefaultResponseCertification::certified_response_headers(vec![
                "Accept-Encoding",
                "Cache-Control",
            ]);
        let response = create_response(CERTIFIED_HEADERS_CEL_EXPRESSION);
        let expected = response_hash(&response, &response_certification, None);

        let filtered = filter_response_headers(&response, &response_certification);
        let header_pairs: Vec<(String, Value)> = filtered
            .headers
            .iter()
            .map(|(k, v)| (k.clone(), Value::String(v.clone())))
            .collect();
        let body_hash = hash(response.body());
        let result =
            response_hash_from_headers(&header_pairs, response.status_code().as_u16(), &body_hash);

        assert_eq!(result, expected);
    }

    fn create_response(cel_expression: &str) -> HttpResponse {
        HttpResponse::ok(
            HELLO_WORLD_BODY,
            vec![
                (CERTIFICATE_HEADER_NAME.into(), CERTIFICATE.into()),
                (
                    CERTIFICATE_EXPRESSION_HEADER_NAME.into(),
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
        )
        .build()
    }

    /// Remove white space from CEL expressions to ease the calculation
    /// of the expected hashes. Generating the hash for a string with so much whitespace manually
    /// may be prone to error in copy/pasting the string into a website and missing a leading/trailing
    /// newline or a tab character somewhere.
    fn remove_whitespace(s: &str) -> String {
        s.chars().filter(|c| !c.is_whitespace()).collect()
    }
}
