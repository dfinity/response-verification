use super::{
    CelExpression, DefaultCertification, DefaultRequestCertification, DefaultResponseCertification,
};

/// Converts a CEL expression from a [CelExpression] object into it's [String] representation.
/// [CelExpression::to_string](CelExpression::to_string()) is an alias of this method and can be used for ergonomics.
pub fn create_cel_expr(certification: &CelExpression) -> String {
    match certification {
        CelExpression::DefaultCertification(certification) => {
            create_default_cel_expr(certification)
        }
    }
}

fn create_default_cel_expr(certification: &Option<DefaultCertification>) -> String {
    let mut cel_expr = String::from("default_certification(ValidationArgs{");

    match certification {
        None => cel_expr.push_str("no_certification:Empty{}"),
        Some(certification) => {
            create_request_cel_expr(&mut cel_expr, certification.request_certification.as_ref());
            create_response_cel_expr(&mut cel_expr, &certification.response_certification);
        }
    }

    cel_expr.push_str("})");
    cel_expr
}

fn create_request_cel_expr(
    cel_expr: &mut String,
    request_certification: Option<&DefaultRequestCertification>,
) {
    match request_certification {
        None => cel_expr.push_str("no_request_certification:Empty{},"),
        Some(request_certification) => {
            cel_expr
                .push_str("request_certification:RequestCertification{certified_request_headers:[");

            if !request_certification.headers.is_empty() {
                cel_expr.push('"');
                cel_expr.push_str(&request_certification.headers.join(r#"",""#));
                cel_expr.push('"');
            }

            cel_expr.push_str("],certified_query_parameters:[");
            if !request_certification.query_parameters.is_empty() {
                cel_expr.push('"');
                cel_expr.push_str(&request_certification.query_parameters.join(r#"",""#));
                cel_expr.push('"');
            }

            cel_expr.push_str("]},");
        }
    }
}

fn create_response_cel_expr(
    cel_expr: &mut String,
    response_certification: &DefaultResponseCertification,
) {
    cel_expr.push_str("response_certification:ResponseCertification{");

    let headers = match response_certification {
        DefaultResponseCertification::CertifiedResponseHeaders(headers) => {
            cel_expr.push_str("certified_response_headers");
            headers
        }
        DefaultResponseCertification::ResponseHeaderExclusions(headers) => {
            cel_expr.push_str("response_header_exclusions");
            headers
        }
    };

    cel_expr.push_str(":ResponseHeaderList{headers:[");
    if !headers.is_empty() {
        cel_expr.push('"');
        cel_expr.push_str(&headers.join(r#"",""#));
        cel_expr.push('"');
    }
    cel_expr.push_str("]}}");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cel::fixtures::*;
    use rstest::*;

    #[rstest]
    #[case::no_certification(no_certification(), no_certification_cel())]
    #[case::no_request_header_inclusions(
        no_request_response_inclusions(),
        no_request_response_inclusions_cel()
    )]
    #[case::no_request_response_exclusions(
        no_request_response_exclusions(),
        no_request_response_exclusions_cel()
    )]
    #[case::no_request_empty_response_inclusions(
        no_request_empty_response_inclusions(),
        no_request_empty_response_inclusions_cel()
    )]
    #[case::no_request_empty_response_exclusions(
        no_request_empty_response_exclusions(),
        no_request_empty_response_exclusions_cel()
    )]
    #[case::include_request_response_header_inclusions(
        include_request_response_header_inclusions(),
        include_request_response_header_inclusions_cel()
    )]
    #[case::include_request_response_header_exclusions(
        include_request_response_header_exclusions(),
        include_request_response_header_exclusions_cel()
    )]
    #[case::include_request_empty_response_inclusions(
        include_request_empty_response_inclusions(),
        include_request_empty_response_inclusions_cel()
    )]
    #[case::include_request_empty_response_exclusions(
        include_request_empty_response_exclusions(),
        include_request_empty_response_exclusions_cel()
    )]
    #[case::empty_request_response_inclusions(
        empty_request_response_inclusions(),
        empty_request_response_inclusions_cel()
    )]
    #[case::empty_request_response_exclusions(
        empty_request_response_exclusions(),
        empty_request_response_exclusions_cel()
    )]
    fn create_cel_expr_test(#[case] certification: CelExpression, #[case] expected: String) {
        let cel_expr = create_cel_expr(&certification);

        assert_eq!(cel_expr, expected);
    }

    fn no_certification() -> CelExpression<'static> {
        CelExpression::DefaultCertification(None)
    }

    fn no_request_response_inclusions() -> CelExpression<'static> {
        CelExpression::DefaultCertification(Some(DefaultCertification {
            request_certification: None,
            response_certification: DefaultResponseCertification::CertifiedResponseHeaders(&[
                "Cache-Control",
                "ETag",
                "Content-Length",
                "Content-Type",
                "Content-Encoding",
            ]),
        }))
    }

    fn no_request_response_exclusions() -> CelExpression<'static> {
        CelExpression::DefaultCertification(Some(DefaultCertification {
            request_certification: None,
            response_certification: DefaultResponseCertification::ResponseHeaderExclusions(&[
                "Date",
                "Cookie",
                "Set-Cookie",
            ]),
        }))
    }

    fn no_request_empty_response_inclusions() -> CelExpression<'static> {
        CelExpression::DefaultCertification(Some(DefaultCertification {
            request_certification: None,
            response_certification: DefaultResponseCertification::CertifiedResponseHeaders(&[]),
        }))
    }

    fn no_request_empty_response_exclusions() -> CelExpression<'static> {
        CelExpression::DefaultCertification(Some(DefaultCertification {
            request_certification: None,
            response_certification: DefaultResponseCertification::ResponseHeaderExclusions(&[]),
        }))
    }

    fn include_request_response_header_inclusions() -> CelExpression<'static> {
        CelExpression::DefaultCertification(Some(DefaultCertification {
            request_certification: Some(DefaultRequestCertification {
                headers: &["Accept", "Accept-Encoding", "If-Match"],
                query_parameters: &["foo", "bar", "baz"],
            }),
            response_certification: DefaultResponseCertification::CertifiedResponseHeaders(&[
                "Cache-Control",
                "ETag",
                "Content-Length",
                "Content-Type",
                "Content-Encoding",
            ]),
        }))
    }

    fn include_request_response_header_exclusions() -> CelExpression<'static> {
        CelExpression::DefaultCertification(Some(DefaultCertification {
            request_certification: Some(DefaultRequestCertification {
                headers: &["Accept", "Accept-Encoding", "If-Match"],
                query_parameters: &["foo", "bar", "baz"],
            }),
            response_certification: DefaultResponseCertification::ResponseHeaderExclusions(&[
                "Date",
                "Cookie",
                "Set-Cookie",
            ]),
        }))
    }

    fn include_request_empty_response_inclusions() -> CelExpression<'static> {
        CelExpression::DefaultCertification(Some(DefaultCertification {
            request_certification: Some(DefaultRequestCertification {
                headers: &["Accept", "Accept-Encoding", "If-Match"],
                query_parameters: &["foo", "bar", "baz"],
            }),
            response_certification: DefaultResponseCertification::CertifiedResponseHeaders(&[]),
        }))
    }

    fn include_request_empty_response_exclusions() -> CelExpression<'static> {
        CelExpression::DefaultCertification(Some(DefaultCertification {
            request_certification: Some(DefaultRequestCertification {
                headers: &["Accept", "Accept-Encoding", "If-Match"],
                query_parameters: &["foo", "bar", "baz"],
            }),
            response_certification: DefaultResponseCertification::ResponseHeaderExclusions(&[]),
        }))
    }

    fn empty_request_response_inclusions() -> CelExpression<'static> {
        CelExpression::DefaultCertification(Some(DefaultCertification {
            request_certification: Some(DefaultRequestCertification {
                headers: &[],
                query_parameters: &[],
            }),
            response_certification: DefaultResponseCertification::CertifiedResponseHeaders(&[]),
        }))
    }

    fn empty_request_response_exclusions() -> CelExpression<'static> {
        CelExpression::DefaultCertification(Some(DefaultCertification {
            request_certification: Some(DefaultRequestCertification {
                headers: &[],
                query_parameters: &[],
            }),
            response_certification: DefaultResponseCertification::ResponseHeaderExclusions(&[]),
        }))
    }
}
