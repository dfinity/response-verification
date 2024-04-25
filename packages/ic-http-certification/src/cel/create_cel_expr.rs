use super::{
    CelExpression, DefaultCelExpression, DefaultFullCelExpression, DefaultRequestCertification,
    DefaultResponseCertification, DefaultResponseCertificationType,
    DefaultResponseOnlyCelExpression,
};

/// Converts a CEL expression from a [CelExpression] struct into it's [String] representation.
///
/// [CelExpression::to_string](CelExpression::to_string()) is an alias of this function and can be used
/// for ergonomics.
pub fn create_cel_expr(certification: &CelExpression) -> String {
    match certification {
        CelExpression::Default(certification) => create_default_cel_expr(certification),
    }
}

/// Converts a CEL expression from a [DefaultCelExpression] struct into it's [String] representation.
///
/// [DefaultCelExpression::to_string](DefaultCelExpression::to_string()) is an alias of this function and
/// can be used for ergonomics.
pub fn create_default_cel_expr(certification: &DefaultCelExpression) -> String {
    match certification {
        DefaultCelExpression::Skip => create_default_skip_cel_expr(),
        DefaultCelExpression::ResponseOnly(certification) => {
            create_default_response_only_cel_expr(certification)
        }
        DefaultCelExpression::Full(certification) => create_default_full_cel_expr(certification),
    }
}

/// Creates the [String] representation of a CEL expression that skips certification entirely.
pub fn create_default_skip_cel_expr() -> String {
    let mut cel_expr = String::from("default_certification(ValidationArgs{");
    cel_expr.push_str("no_certification:Empty{}");
    cel_expr.push_str("})");
    cel_expr
}

/// Converts a CEL expression that only certifies the [HttpResponse](crate::HttpResponse), excluding the
/// [HttpRequest](crate::HttpRequest) from certification, from a [DefaultResponseOnlyCelExpression] struct into
/// it's [String] representation.
///
/// [DefaultResponseOnlyCelExpression::to_string](DefaultResponseOnlyCelExpression::to_string()) is an
/// alias of this method and can be used for ergonomics.
pub fn create_default_response_only_cel_expr(
    certification: &DefaultResponseOnlyCelExpression,
) -> String {
    let mut cel_expr = String::from("default_certification(ValidationArgs{");

    cel_expr.push_str("certification:Certification{");
    cel_expr.push_str("no_request_certification:Empty{},");

    create_response_cel_expr(&mut cel_expr, &certification.response);

    cel_expr.push('}');

    cel_expr.push_str("})");
    cel_expr
}

/// Converts a CEL expression that certifies both the [HttpRequest](crate::HttpRequest) and
/// [HttpResponse](crate::HttpResponse), from a [DefaultFullCelExpression] struct into it's [String] representation.
/// [DefaultFullCelExpression::to_string](DefaultFullCelExpression::to_string()) is an alias of this method and can
/// be used for ergonomics.
pub fn create_default_full_cel_expr(certification: &DefaultFullCelExpression) -> String {
    let mut cel_expr = String::from("default_certification(ValidationArgs{");

    cel_expr.push_str("certification:Certification{");

    create_request_cel_expr(&mut cel_expr, &certification.request);
    create_response_cel_expr(&mut cel_expr, &certification.response);

    cel_expr.push('}');

    cel_expr.push_str("})");
    cel_expr
}

fn create_request_cel_expr(
    cel_expr: &mut String,
    request_certification: &DefaultRequestCertification,
) {
    cel_expr.push_str("request_certification:RequestCertification{certified_request_headers:[");

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

fn create_response_cel_expr(
    cel_expr: &mut String,
    response_certification: &DefaultResponseCertification,
) {
    cel_expr.push_str("response_certification:ResponseCertification{");

    let headers = match response_certification.get_type() {
        DefaultResponseCertificationType::CertifiedResponseHeaders(headers) => {
            cel_expr.push_str("certified_response_headers");
            headers
        }
        DefaultResponseCertificationType::ResponseHeaderExclusions(headers) => {
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
        CelExpression::Default(DefaultCelExpression::Skip)
    }

    fn no_request_response_inclusions() -> CelExpression<'static> {
        CelExpression::Default(DefaultCelExpression::ResponseOnly(
            DefaultResponseOnlyCelExpression {
                response: DefaultResponseCertification::certified_response_headers(vec![
                    "Cache-Control",
                    "ETag",
                    "Content-Length",
                    "Content-Type",
                    "Content-Encoding",
                ]),
            },
        ))
    }

    fn no_request_response_exclusions() -> CelExpression<'static> {
        CelExpression::Default(DefaultCelExpression::ResponseOnly(
            DefaultResponseOnlyCelExpression {
                response: DefaultResponseCertification::response_header_exclusions(vec![
                    "Date",
                    "Cookie",
                    "Set-Cookie",
                ]),
            },
        ))
    }

    fn no_request_empty_response_inclusions() -> CelExpression<'static> {
        CelExpression::Default(DefaultCelExpression::ResponseOnly(
            DefaultResponseOnlyCelExpression {
                response: DefaultResponseCertification::certified_response_headers(vec![]),
            },
        ))
    }

    fn no_request_empty_response_exclusions() -> CelExpression<'static> {
        CelExpression::Default(DefaultCelExpression::ResponseOnly(
            DefaultResponseOnlyCelExpression {
                response: DefaultResponseCertification::response_header_exclusions(vec![]),
            },
        ))
    }

    fn include_request_response_header_inclusions() -> CelExpression<'static> {
        CelExpression::Default(DefaultCelExpression::Full(DefaultFullCelExpression {
            request: DefaultRequestCertification::new(
                vec!["Accept", "Accept-Encoding", "If-Match"],
                vec!["foo", "bar", "baz"],
            ),
            response: DefaultResponseCertification::certified_response_headers(vec![
                "Cache-Control",
                "ETag",
                "Content-Length",
                "Content-Type",
                "Content-Encoding",
            ]),
        }))
    }

    fn include_request_response_header_exclusions() -> CelExpression<'static> {
        CelExpression::Default(DefaultCelExpression::Full(DefaultFullCelExpression {
            request: DefaultRequestCertification::new(
                vec!["Accept", "Accept-Encoding", "If-Match"],
                vec!["foo", "bar", "baz"],
            ),
            response: DefaultResponseCertification::response_header_exclusions(vec![
                "Date",
                "Cookie",
                "Set-Cookie",
            ]),
        }))
    }

    fn include_request_empty_response_inclusions() -> CelExpression<'static> {
        CelExpression::Default(DefaultCelExpression::Full(DefaultFullCelExpression {
            request: DefaultRequestCertification::new(
                vec!["Accept", "Accept-Encoding", "If-Match"],
                vec!["foo", "bar", "baz"],
            ),
            response: DefaultResponseCertification::certified_response_headers(vec![]),
        }))
    }

    fn include_request_empty_response_exclusions() -> CelExpression<'static> {
        CelExpression::Default(DefaultCelExpression::Full(DefaultFullCelExpression {
            request: DefaultRequestCertification::new(
                vec!["Accept", "Accept-Encoding", "If-Match"],
                vec!["foo", "bar", "baz"],
            ),
            response: DefaultResponseCertification::response_header_exclusions(vec![]),
        }))
    }

    fn empty_request_response_inclusions() -> CelExpression<'static> {
        CelExpression::Default(DefaultCelExpression::Full(DefaultFullCelExpression {
            request: DefaultRequestCertification::new(vec![], vec![]),
            response: DefaultResponseCertification::certified_response_headers(vec![]),
        }))
    }

    fn empty_request_response_exclusions() -> CelExpression<'static> {
        CelExpression::Default(DefaultCelExpression::Full(DefaultFullCelExpression {
            request: DefaultRequestCertification::new(vec![], vec![]),
            response: DefaultResponseCertification::response_header_exclusions(vec![]),
        }))
    }
}
