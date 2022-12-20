use crate::Certification;
use nom::branch::alt;
use nom::bytes::complete::{escaped, tag, take_till, take_until, take_while};
use nom::character::complete::{alphanumeric1, char, multispace0, one_of};
use nom::character::is_alphanumeric;
use nom::combinator::{cut, eof, map};
use nom::error::{context, convert_error, ContextError, Error, ParseError, VerboseError};
use nom::multi::separated_list0;
use nom::sequence::{delimited, preceded, separated_pair, terminated, tuple};
use nom::{AsChar, IResult, InputIter, Parser, Slice};
use std::collections::HashMap;
use std::ops::RangeFrom;

#[derive(Debug, Eq, PartialEq)]
pub enum CelValue {
    String(String),
    Array(Vec<CelValue>),
    Object(String, HashMap<String, CelValue>),
    Function(String, Vec<CelValue>),
}

fn trim_whitespace<'a, O, P, E: ParseError<&'a str> + ContextError<&'a str>>(
    parser: P,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
where
    P: Parser<&'a str, O, E>,
{
    context("trim_whitespace", preceded(multispace0, parser))
}

fn drop_separators<'a, O, P, E: ParseError<&'a str> + ContextError<&'a str>>(
    opening_separator: char,
    closing_separator: char,
    parser: P,
) -> impl FnMut(&'a str) -> IResult<&'a str, O, E>
where
    P: Parser<&'a str, O, E>,
{
    context(
        "drop_separators",
        preceded(
            trim_whitespace(char(opening_separator)),
            cut(terminated(parser, trim_whitespace(char(closing_separator)))),
        ),
    )
}

fn ident<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, String, E> {
    let acceptable_special_chars = "_";

    context(
        "parse_ident",
        map(
            take_while(move |e| acceptable_special_chars.contains(e) || is_alphanumeric(e as u8)),
            String::from,
        ),
    )(i)
}

fn parse_str<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, String, E> {
    let acceptable_special_chars = "-";

    context(
        "parse_str",
        map(
            escaped(
                take_while(move |e| {
                    acceptable_special_chars.contains(e) || is_alphanumeric(e as u8)
                }),
                '\\',
                one_of("\"n\\"),
            ),
            String::from,
        ),
    )(i)
}

fn string<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, String, E> {
    context("string", drop_separators('\"', '\"', parse_str))(i)
}

fn array<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, Vec<CelValue>, E> {
    context(
        "array",
        drop_separators(
            '[',
            ']',
            separated_list0(trim_whitespace(char(',')), cel_value),
        ),
    )(i)
}

fn key_value<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, (String, CelValue), E> {
    context(
        "key_value",
        separated_pair(
            trim_whitespace(ident),
            trim_whitespace(char(':')),
            cel_value,
        ),
    )(i)
}

fn object<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, (String, HashMap<String, CelValue>), E> {
    context(
        "object",
        tuple((
            ident,
            drop_separators(
                '{',
                '}',
                map(
                    separated_list0(trim_whitespace(char(',')), key_value),
                    |tuple_vec| tuple_vec.into_iter().collect(),
                ),
            ),
        )),
    )(i)
}

fn function<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, (String, Vec<CelValue>), E> {
    context(
        "function",
        tuple((
            ident,
            drop_separators(
                '(',
                ')',
                map(
                    separated_list0(trim_whitespace(char(',')), cel_value),
                    |tuple_vec| tuple_vec.into_iter().collect(),
                ),
            ),
        )),
    )(i)
}

fn cel_value<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, CelValue, E> {
    trim_whitespace(alt((
        map(object, |(name, value)| CelValue::Object(name, value)),
        map(function, |(name, value)| CelValue::Function(name, value)),
        map(array, CelValue::Array),
        map(string, CelValue::String),
    )))(i)
}

// [TODO] - Create concrete error type instead of just "String"
pub fn parse_cel_expression(i: &str) -> Result<CelValue, String> {
    // [TODO] - Create "debug" feature flag to toggle on verbose errors
    let result = cel_value::<VerboseError<&str>>(i);

    match result {
        Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
            // [TODO] - Create "debug" feature flag to toggle on stacktrace
            let stacktrace = convert_error(i, e);

            Err(stacktrace)
        }
        Err(e) => Err(e.to_string()),
        Ok((_remaining, result)) => Ok(result),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::error::{convert_error, VerboseError};

    #[test]
    fn parses_no_certification_expression() {
        let cel_expression = r#"
            default_certification (
              ValidationArgs {
                no_certification: Empty { }
              }
            )
        "#;

        let result = parse_cel_expression(cel_expression).unwrap();

        assert_eq!(
            result,
            CelValue::Function(
                "default_certification".into(),
                vec![CelValue::Object(
                    "ValidationArgs".into(),
                    HashMap::from([(
                        "no_certification".into(),
                        CelValue::Object("Empty".into(), HashMap::from([]))
                    )]),
                )],
            )
        );
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

        let result = parse_cel_expression(cel_expression).unwrap();

        assert_eq!(
            result,
            CelValue::Function(
                "default_certification".into(),
                vec![CelValue::Object(
                    "ValidationArgs".into(),
                    HashMap::from([(
                        "certification".into(),
                        CelValue::Object(
                            "Certification".into(),
                            HashMap::from([
                                (
                                    "no_request_certification".into(),
                                    CelValue::Object("Empty".into(), HashMap::from([]))
                                ),
                                (
                                    "response_certification".into(),
                                    CelValue::Object(
                                        "ResponseCertification".into(),
                                        HashMap::from([(
                                            "response_header_exclusions".into(),
                                            CelValue::Object(
                                                "ResponseHeaderList".into(),
                                                HashMap::from([(
                                                    "headers".into(),
                                                    CelValue::Array(vec![
                                                        CelValue::String("Server".into()),
                                                        CelValue::String("Date".into()),
                                                        CelValue::String("X-Cache-Status".into()),
                                                    ])
                                                )]),
                                            )
                                        )]),
                                    )
                                )
                            ]),
                        )
                    )]),
                )],
            )
        );
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

        let result = parse_cel_expression(cel_expression).unwrap();

        assert_eq!(
            result,
            CelValue::Function(
                "default_certification".into(),
                vec![CelValue::Object(
                    "ValidationArgs".into(),
                    HashMap::from([(
                        "certification".into(),
                        CelValue::Object(
                            "Certification".into(),
                            HashMap::from([
                                (
                                    "request_certification".into(),
                                    CelValue::Object(
                                        "RequestCertification".into(),
                                        HashMap::from([
                                            (
                                                "certified_request_headers".into(),
                                                CelValue::Array(vec![CelValue::String(
                                                    "host".into()
                                                )])
                                            ),
                                            (
                                                "certified_query_parameters".into(),
                                                CelValue::Array(vec![CelValue::String(
                                                    "filter".into()
                                                )])
                                            ),
                                        ]),
                                    )
                                ),
                                (
                                    "response_certification".into(),
                                    CelValue::Object(
                                        "ResponseCertification".into(),
                                        HashMap::from([(
                                            "certified_response_headers".into(),
                                            CelValue::Object(
                                                "ResponseHeaderList".into(),
                                                HashMap::from([(
                                                    "headers".into(),
                                                    CelValue::Array(vec![
                                                        CelValue::String("Content-Type".into()),
                                                        CelValue::String("X-Frame-Options".into()),
                                                        CelValue::String(
                                                            "Content-Security-Policy".into()
                                                        ),
                                                        CelValue::String(
                                                            "Strict-Transport-Security".into()
                                                        ),
                                                        CelValue::String("Referrer-Policy".into()),
                                                        CelValue::String(
                                                            "Permissions-Policy".into()
                                                        ),
                                                    ])
                                                )]),
                                            )
                                        )]),
                                    )
                                )
                            ]),
                        )
                    )]),
                )],
            )
        );
    }
}
