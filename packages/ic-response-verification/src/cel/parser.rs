use crate::cel::error::{CelParserError, CelParserResult};
use nom::branch::alt;
use nom::bytes::complete::{escaped, take_while};
use nom::character::complete::{char, multispace0, one_of};
use nom::character::is_alphanumeric;
use nom::combinator::{cut, map};
use nom::error::{context, ContextError, ParseError};
use nom::multi::separated_list0;
use nom::sequence::{preceded, separated_pair, terminated, tuple};
use nom::{IResult, Parser};
use std::collections::HashMap;
use std::fmt;

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum CelValue<'a> {
    String(&'a str),
    Array(Vec<CelValue<'a>>),
    Object(&'a str, HashMap<&'a str, CelValue<'a>>),
    Function(&'a str, Vec<CelValue<'a>>),
}

impl<'a> fmt::Display for CelValue<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
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
) -> IResult<&'a str, &'a str, E> {
    let acceptable_special_chars = "_";

    context(
        "parse_ident",
        take_while(move |e| acceptable_special_chars.contains(e) || is_alphanumeric(e as u8)),
    )(i)
}

fn parse_str<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, &'a str, E> {
    let acceptable_special_chars = "-";

    context(
        "parse_str",
        escaped(
            take_while(move |e| acceptable_special_chars.contains(e) || is_alphanumeric(e as u8)),
            '\\',
            one_of("\"n\\"),
        ),
    )(i)
}

fn string<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, &'a str, E> {
    context("string", drop_separators('\"', '\"', parse_str))(i)
}

fn array<'a, E: ParseError<&'a str> + ContextError<&'a str>>(
    i: &'a str,
) -> IResult<&'a str, Vec<CelValue<'a>>, E> {
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
) -> IResult<&'a str, (&'a str, CelValue<'a>), E> {
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
) -> IResult<&'a str, (&'a str, HashMap<&'a str, CelValue<'a>>), E> {
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
) -> IResult<&'a str, (&'a str, Vec<CelValue<'a>>), E> {
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
) -> IResult<&'a str, CelValue<'a>, E> {
    context(
        "cel_value",
        trim_whitespace(alt((
            map(object, |(name, value)| CelValue::Object(name, value)),
            map(function, |(name, value)| CelValue::Function(name, value)),
            map(array, CelValue::Array),
            map(string, CelValue::String),
        ))),
    )(i)
}

pub(crate) fn parse_cel_expression(i: &str) -> CelParserResult<CelValue> {
    #[cfg(feature = "debug")]
    let result = cel_value::<nom::error::VerboseError<&str>>(i);

    #[cfg(not(feature = "debug"))]
    let result = cel_value::<nom::error::Error<&str>>(i);

    match result {
        #[cfg(feature = "debug")]
        Err(nom::Err::Error(e)) | Err(nom::Err::Failure(e)) => {
            let stacktrace = nom::error::convert_error(i, e);

            Err(CelParserError::CelSyntaxException(stacktrace))
        }
        Err(e) => Err(CelParserError::CelSyntaxException(e.to_string())),
        Ok((_remaining, result)) => Ok(result),
    }
}
