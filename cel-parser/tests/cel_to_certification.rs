use cel_parser::{
    cel_to_certification, Certification, RequestCertification, ResponseCertification,
};

fn remove_whitespace(s: &str) -> String {
    s.chars().filter(|c| !c.is_whitespace()).collect()
}

fn assert_parse_result(cel_expression: &str, expected_result: Option<Certification>) {
    let minified_cel_expression = &remove_whitespace(cel_expression);

    let result = cel_to_certification(cel_expression).unwrap();
    let minified_result = cel_to_certification(minified_cel_expression).unwrap();

    assert_eq!(result, expected_result);
    assert_eq!(minified_result, expected_result);
}

#[test]
fn parses_no_certification_expression() {
    let cel_expression = r#"
            default_certification (
              ValidationArgs {
                no_certification: Empty { }
              }
            )
        "#;
    let expected_result = None;

    assert_parse_result(cel_expression, expected_result);
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
        "#;
    let expected_result = Some(Certification {
        request_certification: None,
        response_certification: ResponseCertification::HeaderExclusions(vec![
            "Server".into(),
            "Date".into(),
            "X-Cache-Status".into(),
        ]),
    });

    assert_parse_result(cel_expression, expected_result);
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
                            certified_response_headers: ResponseHeaderList {
                                headers: ["Content-Type","X-Frame-Options","Content-Security-Policy","Strict-Transport-Security","Referrer-Policy","Permissions-Policy"]
                            }
                        }
                    }
                }
            )
        "#;
    let expected_result = Some(Certification {
        request_certification: Some(RequestCertification {
            certified_request_headers: vec!["host".into()],
            certified_query_parameters: vec!["filter".into()],
        }),
        response_certification: ResponseCertification::CertifiedHeaders(vec![
            "Content-Type".into(),
            "X-Frame-Options".into(),
            "Content-Security-Policy".into(),
            "Strict-Transport-Security".into(),
            "Referrer-Policy".into(),
            "Permissions-Policy".into(),
        ]),
    });

    assert_parse_result(cel_expression, expected_result);
}
