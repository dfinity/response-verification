use crate::cel::{map_cel_ast, parse_cel_expression};
use ic_http_certification::{
    cel::{
        CelExpression, DefaultCelExpression, DefaultFullCelExpression, DefaultRequestCertification,
        DefaultResponseOnlyCelExpression,
    },
    DefaultResponseCertification,
};
use ic_response_verification_test_utils::remove_whitespace;

#[test]
fn parses_no_certification_expression() {
    let cel_expression = r#"
        default_certification (
            ValidationArgs {
                no_certification: Empty { }
            }
        )
    "#
    .to_string();
    let expected_result = CelExpression::Default(DefaultCelExpression::Skip);

    let parsed_cel_expr = parse_cel_expression(&cel_expression).unwrap();
    let result = map_cel_ast(&parsed_cel_expr).unwrap();

    let minified_cel_expression = remove_whitespace(&cel_expression);
    let parsed_min_cel_expr = parse_cel_expression(&minified_cel_expression).unwrap();
    let minified_result = map_cel_ast(&parsed_min_cel_expr).unwrap();

    assert_eq!(&result, &expected_result);
    assert_eq!(&minified_result, &expected_result);
}

#[test]
fn parses_no_request_certification_expression() {
    let cel_expression = r#"
        default_certification (
            ValidationArgs {
                certification: Certification {
                    no_request_certification: Empty {},
                    response_certification: ResponseCertification {
                        response_header_exclusions: ResponseHeaderList {
                            headers: ["Server","Date","X-Cache-Status"]
                        }
                    }
                }
            }
        )
    "#
    .to_string();
    let expected_result = CelExpression::Default(DefaultCelExpression::ResponseOnly(
        DefaultResponseOnlyCelExpression {
            response: DefaultResponseCertification::response_header_exclusions(vec![
                "Server",
                "Date",
                "X-Cache-Status",
            ]),
        },
    ));

    let parsed_cel_expr = parse_cel_expression(&cel_expression).unwrap();
    let result = map_cel_ast(&parsed_cel_expr).unwrap();

    let minified_cel_expression = remove_whitespace(&cel_expression);
    let parsed_min_cel_expr = parse_cel_expression(&minified_cel_expression).unwrap();
    let minified_result = map_cel_ast(&parsed_min_cel_expr).unwrap();

    assert_eq!(&result, &expected_result);
    assert_eq!(&minified_result, &expected_result);
}

#[test]
fn parses_full_certification_expression() {
    let cel_expression = r#"
        default_certification (
            ValidationArgs {
                certification: Certification {
                    request_certification: RequestCertification {
                        certified_request_headers: ["host"],
                        certified_query_parameters: ["filter"]
                    },
                    response_certification: ResponseCertification {
                        response_header_exclusions: ResponseHeaderList {
                            headers: ["Content-Type","X-Frame-Options","Content-Security-Policy","Strict-Transport-Security","Referrer-Policy","Permissions-Policy"]
                        }
                    }
                }
            }
        )
    "#.to_string();
    let expected_result =
        CelExpression::Default(DefaultCelExpression::Full(DefaultFullCelExpression {
            request: DefaultRequestCertification::new(vec!["host"], vec!["filter"]),
            response: DefaultResponseCertification::response_header_exclusions(vec![
                "Content-Type",
                "X-Frame-Options",
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "Referrer-Policy",
                "Permissions-Policy",
            ]),
        }));

    let parsed_cel_expr = parse_cel_expression(&cel_expression).unwrap();
    let result = map_cel_ast(&parsed_cel_expr).unwrap();

    let minified_cel_expression = remove_whitespace(&cel_expression);
    let parsed_min_cel_expr = parse_cel_expression(&minified_cel_expression).unwrap();
    let minified_result = map_cel_ast(&parsed_min_cel_expr).unwrap();

    assert_eq!(&result, &expected_result);
    assert_eq!(&minified_result, &expected_result);
}
