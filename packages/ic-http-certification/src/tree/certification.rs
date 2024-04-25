use crate::{
    request_hash, response_hash, DefaultCelBuilder, DefaultFullCelExpression,
    DefaultResponseOnlyCelExpression, HttpCertificationError, HttpCertificationResult, HttpRequest,
    HttpResponse,
};
use ic_certification::Hash;
use ic_representation_independent_hash::hash;
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpCertificationType {
    Skip {
        cel_expr_hash: Hash,
    },
    ResponseOnly {
        cel_expr_hash: Hash,
        response_hash: Hash,
    },
    Full {
        cel_expr_hash: Hash,
        request_hash: Hash,
        response_hash: Hash,
    },
}

/// A certified [HttpRequest] and [HttpResponse] pair.
///
/// It supports three types of certification via associated functions:
///
/// - [skip()](HttpCertification::skip()) excludes both an [HttpRequest] and the
/// corresponding [HttpResponse] from certification.
///
/// - [response_only()](HttpCertification::response_only()) includes an
/// [HttpResponse] but excludes the corresponding [HttpRequest]
/// from certification.
///
/// - [full()](HttpCertification::full()) includes both an [HttpResponse] and
/// the corresponding [HttpRequest] in certification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpCertification(HttpCertificationType);

impl HttpCertification {
    /// Creates a certification that excludes both the [HttpRequest] and
    /// the corresponding [HttpResponse].
    pub fn skip() -> HttpCertification {
        let cel_expr = DefaultCelBuilder::skip_certification().to_string();
        let cel_expr_hash = hash(cel_expr.as_bytes());

        Self(HttpCertificationType::Skip { cel_expr_hash })
    }

    /// Creates a certification that includes an [HttpResponse], but excludes the
    /// corresponding [HttpRequest].
    pub fn response_only(
        cel_expr_def: &DefaultResponseOnlyCelExpression,
        response: &HttpResponse,
        response_body_hash: Option<Hash>,
    ) -> HttpCertificationResult<HttpCertification> {
        let cel_expr = cel_expr_def.to_string();
        Self::validate_response(response, &cel_expr)?;

        let cel_expr_hash = hash(cel_expr.as_bytes());
        let response_hash = response_hash(response, &cel_expr_def.response, response_body_hash);

        Ok(Self(HttpCertificationType::ResponseOnly {
            cel_expr_hash,
            response_hash,
        }))
    }

    /// Creates a certification that includes both an [HttpResponse] and the corresponding
    /// [HttpRequest].
    pub fn full(
        cel_expr_def: &DefaultFullCelExpression,
        request: &HttpRequest,
        response: &HttpResponse,
        response_body_hash: Option<Hash>,
    ) -> HttpCertificationResult<HttpCertification> {
        let cel_expr = cel_expr_def.to_string();
        Self::validate_response(response, &cel_expr)?;

        let cel_expr_hash = hash(cel_expr.as_bytes());
        let request_hash = request_hash(request, &cel_expr_def.request)?;
        let response_hash = response_hash(response, &cel_expr_def.response, response_body_hash);

        Ok(Self(HttpCertificationType::Full {
            cel_expr_hash,
            request_hash,
            response_hash,
        }))
    }

    pub(crate) fn to_tree_path(self) -> Vec<Vec<u8>> {
        match self.0 {
            HttpCertificationType::Skip { cel_expr_hash } => vec![cel_expr_hash.to_vec()],
            HttpCertificationType::ResponseOnly {
                cel_expr_hash,
                response_hash,
            } => vec![
                cel_expr_hash.to_vec(),
                "".as_bytes().to_vec(),
                response_hash.to_vec(),
            ],
            HttpCertificationType::Full {
                cel_expr_hash,
                request_hash,
                response_hash,
            } => vec![
                cel_expr_hash.to_vec(),
                request_hash.to_vec(),
                response_hash.to_vec(),
            ],
        }
    }

    fn validate_response(response: &HttpResponse, cel_expr: &str) -> HttpCertificationResult {
        let mut found_header = false;

        for (header_name, header_value) in &response.headers {
            if header_name.to_lowercase() == "ic-certificateexpression" {
                match header_value == cel_expr {
                    true => {
                        if found_header {
                            return Err(
                                HttpCertificationError::MultipleCertificateExpressionHeaders {
                                    expected: cel_expr.to_string(),
                                },
                            );
                        }

                        found_header = true;
                    }
                    false => {
                        return Err(
                            HttpCertificationError::CertificateExpressionHeaderMismatch {
                                expected: cel_expr.to_string(),
                                actual: header_value.clone(),
                            },
                        )
                    }
                };
            }
        }

        if found_header {
            Ok(())
        } else {
            Err(HttpCertificationError::CertificateExpressionHeaderMissing {
                expected: cel_expr.to_string(),
            })
        }
    }
}

impl<'a> From<HttpCertification> for Cow<'a, HttpCertification> {
    fn from(cert: HttpCertification) -> Cow<'a, HttpCertification> {
        Cow::Owned(cert)
    }
}

impl<'a> From<&'a HttpCertification> for Cow<'a, HttpCertification> {
    fn from(cert: &'a HttpCertification) -> Cow<'a, HttpCertification> {
        Cow::Borrowed(cert)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DefaultResponseCertification;
    use rstest::*;

    #[rstest]
    fn no_certification() {
        let cel_expr = DefaultCelBuilder::skip_certification().to_string();
        let expected_cel_expr_hash = hash(cel_expr.as_bytes());

        let result = HttpCertification::skip();

        assert!(matches!(
            result.0,
            HttpCertificationType::Skip { cel_expr_hash } if cel_expr_hash == expected_cel_expr_hash
        ));
        assert_eq!(result.to_tree_path(), vec![expected_cel_expr_hash.to_vec()]);
    }

    #[rstest]
    fn response_only_certification() {
        let cel_expr = DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["ETag", "Cache-Control"],
            ))
            .build();
        let expected_cel_expr_hash = hash(cel_expr.to_string().as_bytes());

        let response = &HttpResponse {
            status_code: 200,
            body: vec![],
            headers: vec![("IC-CertificateExpression".to_string(), cel_expr.to_string())],
            upgrade: None,
        };
        let expected_response_hash = response_hash(response, &cel_expr.response, None);

        let result = HttpCertification::response_only(&cel_expr, response, None).unwrap();

        assert!(matches!(
            result.0,
            HttpCertificationType::ResponseOnly {
                cel_expr_hash,
                response_hash
            } if cel_expr_hash == expected_cel_expr_hash &&
                response_hash == expected_response_hash
        ));
        assert_eq!(
            result.to_tree_path(),
            vec![
                expected_cel_expr_hash.to_vec(),
                "".as_bytes().to_vec(),
                expected_response_hash.to_vec()
            ]
        );
    }

    #[rstest]
    fn response_only_certification_without_expression_header() {
        let cel_expr = DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["ETag", "Cache-Control"],
            ))
            .build();

        let response = &HttpResponse {
            status_code: 200,
            body: vec![],
            headers: vec![],
            upgrade: None,
        };

        let result = HttpCertification::response_only(&cel_expr, response, None).unwrap_err();

        assert!(matches!(
            result,
            HttpCertificationError::CertificateExpressionHeaderMissing { expected } if expected == cel_expr.to_string()
        ));
    }

    #[rstest]
    fn response_only_certification_with_wrong_expression_header() {
        let cel_expr = DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["ETag", "Cache-Control"],
            ))
            .build();
        let wrong_cel_expr = DefaultCelBuilder::full_certification().build();

        let response = &HttpResponse {
            status_code: 200,
            body: vec![],
            headers: vec![(
                "IC-CertificateExpression".to_string(),
                wrong_cel_expr.to_string(),
            )],
            upgrade: None,
        };

        let result = HttpCertification::response_only(&cel_expr, response, None).unwrap_err();

        assert!(matches!(
            result,
            HttpCertificationError::CertificateExpressionHeaderMismatch { expected, actual }
                if expected == cel_expr.to_string()
                && actual == wrong_cel_expr.to_string()
        ));
    }

    #[rstest]
    fn response_only_certification_with_multiple_expression_headers() {
        let cel_expr = DefaultCelBuilder::response_only_certification()
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["ETag", "Cache-Control"],
            ))
            .build();

        let response = &HttpResponse {
            status_code: 200,
            body: vec![],
            headers: vec![
                ("IC-CertificateExpression".to_string(), cel_expr.to_string()),
                ("IC-CertificateExpression".to_string(), cel_expr.to_string()),
            ],
            upgrade: None,
        };

        let result = HttpCertification::response_only(&cel_expr, response, None).unwrap_err();

        assert!(matches!(
            result,
            HttpCertificationError::MultipleCertificateExpressionHeaders { expected } if expected == cel_expr.to_string()
        ));
    }

    #[rstest]
    fn full_certification() {
        let cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["If-Match"])
            .with_request_query_parameters(vec!["foo", "bar", "baz"])
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["ETag", "Cache-Control"],
            ))
            .build();
        let expected_cel_expr_hash = hash(cel_expr.to_string().as_bytes());

        let request = &HttpRequest {
            body: vec![],
            headers: vec![],
            method: "GET".to_string(),
            url: "/index.html".to_string(),
        };
        let expected_request_hash = request_hash(request, &cel_expr.request).unwrap();

        let response = &HttpResponse {
            status_code: 200,
            body: vec![],
            headers: vec![("IC-CertificateExpression".to_string(), cel_expr.to_string())],
            upgrade: None,
        };
        let expected_response_hash = response_hash(response, &cel_expr.response, None);

        let result = HttpCertification::full(&cel_expr, request, response, None).unwrap();

        assert!(matches!(
            result.0,
            HttpCertificationType::Full {
                cel_expr_hash,
                request_hash,
                response_hash
            } if cel_expr_hash == expected_cel_expr_hash &&
                request_hash == expected_request_hash &&
                response_hash == expected_response_hash
        ));
        assert_eq!(
            result.to_tree_path(),
            vec![
                expected_cel_expr_hash.to_vec(),
                expected_request_hash.to_vec(),
                expected_response_hash.to_vec()
            ]
        );
    }

    #[rstest]
    fn full_certification_without_expression_header() {
        let cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["If-Match"])
            .with_request_query_parameters(vec!["foo", "bar", "baz"])
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["ETag", "Cache-Control"],
            ))
            .build();

        let request = &HttpRequest {
            body: vec![],
            headers: vec![],
            method: "GET".to_string(),
            url: "/index.html".to_string(),
        };

        let response = &HttpResponse {
            status_code: 200,
            body: vec![],
            headers: vec![],
            upgrade: None,
        };

        let result = HttpCertification::full(&cel_expr, request, response, None).unwrap_err();

        assert!(matches!(
            result,
            HttpCertificationError::CertificateExpressionHeaderMissing { expected } if expected == cel_expr.to_string()
        ));
    }

    #[rstest]
    fn full_certification_with_wrong_expression_header() {
        let cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["If-Match"])
            .with_request_query_parameters(vec!["foo", "bar", "baz"])
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["ETag", "Cache-Control"],
            ))
            .build();
        let wrong_cel_expr = DefaultCelBuilder::response_only_certification().build();

        let request = &HttpRequest {
            body: vec![],
            headers: vec![],
            method: "GET".to_string(),
            url: "/index.html".to_string(),
        };

        let response = &HttpResponse {
            status_code: 200,
            body: vec![],
            headers: vec![(
                "IC-CertificateExpression".to_string(),
                wrong_cel_expr.to_string(),
            )],
            upgrade: None,
        };

        let result = HttpCertification::full(&cel_expr, request, response, None).unwrap_err();

        assert!(matches!(
            result,
            HttpCertificationError::CertificateExpressionHeaderMismatch { expected, actual }
                if expected == cel_expr.to_string()
                && actual == wrong_cel_expr.to_string()
        ));
    }

    #[rstest]
    fn full_certification_with_multiple_expression_headers() {
        let cel_expr = DefaultCelBuilder::full_certification()
            .with_request_headers(vec!["If-Match"])
            .with_request_query_parameters(vec!["foo", "bar", "baz"])
            .with_response_certification(DefaultResponseCertification::certified_response_headers(
                vec!["ETag", "Cache-Control"],
            ))
            .build();

        let request = &HttpRequest {
            body: vec![],
            headers: vec![],
            method: "GET".to_string(),
            url: "/index.html".to_string(),
        };

        let response = &HttpResponse {
            status_code: 200,
            body: vec![],
            headers: vec![
                ("IC-CertificateExpression".to_string(), cel_expr.to_string()),
                ("IC-CertificateExpression".to_string(), cel_expr.to_string()),
            ],
            upgrade: None,
        };

        let result = HttpCertification::full(&cel_expr, request, response, None).unwrap_err();

        assert!(matches!(
            result,
            HttpCertificationError::MultipleCertificateExpressionHeaders { expected } if expected == cel_expr.to_string()
        ));
    }
}
