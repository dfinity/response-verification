use crate::{CborError, CborResult};
use candid::Principal;
use nom::{
    bytes::complete::take,
    combinator::{eof, map, peek},
    error::{Error, ErrorKind},
    multi::{count, fold_many_m_n},
    number::complete::{be_u16, be_u32, be_u64, be_u8},
    sequence::terminated,
    Err, IResult,
};
use std::{collections::HashMap, fmt};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CborNegativeInt {
    Int8(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum CborUnsignedInt {
    UInt8(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
}

impl CborUnsignedInt {
    fn to_usize(self) -> usize {
        match self {
            CborUnsignedInt::UInt8(v) => v as usize,
            CborUnsignedInt::UInt16(v) => v as usize,
            CborUnsignedInt::UInt32(v) => v as usize,
            CborUnsignedInt::UInt64(v) => v as usize,
        }
    }

    // https://www.rfc-editor.org/rfc/rfc8949.html#section-3.1
    // The value of a Cbor Major type 1 (negative int) is encoded as its positive counterpart - 1
    // For example: -5 is encoded as 4
    // So to decode the value we take -1 - n where n is the encoded value
    // For example: -1 - 4 = -5
    fn to_negative(self) -> CborNegativeInt {
        match self {
            CborUnsignedInt::UInt8(n) => CborNegativeInt::Int8(-1 - (n as i8)),
            CborUnsignedInt::UInt16(n) => CborNegativeInt::Int16(-1 - (n as i16)),
            CborUnsignedInt::UInt32(n) => CborNegativeInt::Int32(-1 - (n as i32)),
            CborUnsignedInt::UInt64(n) => CborNegativeInt::Int64(-1 - (n as i64)),
        }
    }

    fn to_u8(self) -> Result<u8, String> {
        Ok(match self {
            CborUnsignedInt::UInt8(n) => n,
            _ => return Err(String::from("Expected u8")),
        })
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CborHashTree {
    Empty,
    Fork,
    Labelled,
    Leaf,
    Pruned,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CborValue {
    Unsigned(CborUnsignedInt),
    Signed(CborNegativeInt),
    ByteString(Vec<u8>),
    Array(Vec<CborValue>),
    Map(HashMap<String, CborValue>),
    HashTree(CborHashTree),
}

impl fmt::Display for CborValue {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Cbor major type information is stored in the high-order 3 bits.
const fn get_cbor_type(e: u8) -> u8 {
    (e & 0b1110_0000) >> 5
}

fn extract_cbor_type(i: &[u8]) -> IResult<&[u8], u8> {
    map(be_u8, get_cbor_type)(i)
}

fn peek_cbor_type(i: &[u8]) -> IResult<&[u8], u8> {
    peek(extract_cbor_type)(i)
}

/// Additional cbor information is stored in the low-order 5 bits.
/// This additional information can be a value,
/// or the size of a value contained in the following bytes.
const fn get_cbor_info(e: u8) -> u8 {
    e & 0b0001_1111
}

fn extract_cbor_info(i: &[u8]) -> IResult<&[u8], u8> {
    map(be_u8, get_cbor_info)(i)
}

fn extract_cbor_value(i: &[u8]) -> IResult<&[u8], CborUnsignedInt> {
    let (i, cbor_info) = extract_cbor_info(i)?;

    match cbor_info {
        _n @ 0..=23 => Ok((i, CborUnsignedInt::UInt8(cbor_info))),
        24 => map(be_u8, CborUnsignedInt::UInt8)(i),
        25 => map(be_u16, CborUnsignedInt::UInt16)(i),
        26 => map(be_u32, CborUnsignedInt::UInt32)(i),
        27 => map(be_u64, CborUnsignedInt::UInt64)(i),
        _ => Err(Err::Error(Error::new(i, ErrorKind::Alt))),
    }
}

fn extract_key_val_pair(i: &[u8]) -> IResult<&[u8], (String, CborValue)> {
    let (i, key) = parser(i)?;

    let key = match key {
        CborValue::ByteString(byte_string) => match String::from_utf8(byte_string) {
            Ok(str) => Ok(str),
            _ => Err(Err::Error(Error::new(i, ErrorKind::Alt))),
        },
        _ => Err(Err::Error(Error::new(i, ErrorKind::Alt))),
    }?;

    let (i, val) = parser(i)?;

    Ok((i, (key, val)))
}

fn parser(i: &[u8]) -> IResult<&[u8], CborValue> {
    let (i, cbor_type) = peek_cbor_type(i)?;
    let (i, cbor_value) = extract_cbor_value(i)?;

    return match cbor_type {
        0 => {
            // Hash Tree nodes are encoded as unsigned int instead of tagged data items,
            // if we ever need to decode an actual unsigned int with a value 0-4 then this will break
            Ok((
                i,
                match cbor_value.to_u8() {
                    Ok(0) => CborValue::HashTree(CborHashTree::Empty),
                    Ok(1) => CborValue::HashTree(CborHashTree::Fork),
                    Ok(2) => CborValue::HashTree(CborHashTree::Labelled),
                    Ok(3) => CborValue::HashTree(CborHashTree::Leaf),
                    Ok(4) => CborValue::HashTree(CborHashTree::Pruned),
                    _ => CborValue::Unsigned(cbor_value),
                },
            ))
        }

        1 => Ok((i, CborValue::Signed(cbor_value.to_negative()))),

        2 | 3 => {
            let data_len = cbor_value.to_usize();
            let (i, data) = take(data_len)(i)?;

            Ok((i, CborValue::ByteString(data.to_vec())))
        }

        4 => {
            let data_len = cbor_value.to_usize();
            let (i, data) = count(parser, data_len)(i)?;

            Ok((i, CborValue::Array(data)))
        }

        5 => {
            let data_len = cbor_value.to_usize();
            let (i, data) = fold_many_m_n(
                0,
                data_len,
                extract_key_val_pair,
                || HashMap::with_capacity(data_len),
                |mut acc, (key, val)| {
                    acc.insert(key, val);
                    acc
                },
            )(i)?;

            Ok((i, CborValue::Map(data)))
        }

        // ignore custom data tags and floats, we don't currently need them
        6 => parser(i),
        7 => parser(i),

        _ => Err(Err::Error(Error::new(i, ErrorKind::Alt))),
    };
}

pub fn parse_cbor(i: &[u8]) -> Result<CborValue, nom::Err<Error<&[u8]>>> {
    let (_remaining, result) = terminated(parser, eof)(i)?;

    Ok(result)
}

pub fn parse_cbor_principals_array(i: &[u8]) -> CborResult<Vec<(Principal, Principal)>> {
    let parsed_cbor = parse_cbor(i).map_err(|e| CborError::MalformedCbor(e.to_string()))?;

    let CborValue::Array(ranges_entries) = parsed_cbor else {
        return Err(CborError::MalformedCborCanisterRanges);
    };

    ranges_entries
        .iter()
        .map(|ranges_entry| {
            let CborValue::Array(range) = ranges_entry else {
                return Err(CborError::MalformedCborCanisterRanges);
            };

            let (first_principal, second_principal) = match (range.first(), range.get(1)) {
                (Some(CborValue::ByteString(a)), Some(CborValue::ByteString(b))) => (a, b),
                _ => return Err(CborError::MalformedCborCanisterRanges),
            };

            Ok((
                Principal::from_slice(first_principal),
                Principal::from_slice(second_principal),
            ))
        })
        .collect::<Result<_, _>>()
}

pub fn parse_cbor_string_array(i: &[u8]) -> CborResult<Vec<String>> {
    let parsed_cbor = parse_cbor(i).map_err(|e| CborError::MalformedCbor(e.to_string()))?;

    let CborValue::Array(elems) = parsed_cbor else {
        return Err(CborError::UnexpectedCborNodeType {
            expected_type: "Array".into(),
            found_type: parsed_cbor.to_string(),
        });
    };

    elems
        .iter()
        .map(|elem| {
            let CborValue::ByteString(elem) = elem else {
                return Err(CborError::UnexpectedCborNodeType {
                    expected_type: "ByteString".into(),
                    found_type: elem.to_string(),
                });
            };

            String::from_utf8(elem.to_owned()).map_err(CborError::Utf8ConversionError)
        })
        .collect::<Result<_, _>>()
}

/// Testing examples from the Cbor spec: https://www.rfc-editor.org/rfc/rfc8949.html#name-examples-of-encoded-cbor-da
#[cfg(test)]
mod tests {
    use super::*;
    use ic_response_verification_test_utils::{cbor_encode, hex_decode};

    #[test]
    fn decodes_arrays() {
        let cbor_hex = "83070809";
        let cbor = hex_decode(cbor_hex);

        let result = parse_cbor(cbor.as_slice()).unwrap();

        assert_eq!(
            result,
            CborValue::Array(vec![
                CborValue::Unsigned(CborUnsignedInt::UInt8(7)),
                CborValue::Unsigned(CborUnsignedInt::UInt8(8)),
                CborValue::Unsigned(CborUnsignedInt::UInt8(9)),
            ])
        );
    }

    #[test]
    fn decodes_nested_arrays() {
        let cbor_hex = "8307820809820A0B";
        let cbor = hex_decode(cbor_hex);

        let result = parse_cbor(cbor.as_slice()).unwrap();

        assert_eq!(
            result,
            CborValue::Array(vec![
                CborValue::Unsigned(CborUnsignedInt::UInt8(7)),
                CborValue::Array(vec![
                    CborValue::Unsigned(CborUnsignedInt::UInt8(8)),
                    CborValue::Unsigned(CborUnsignedInt::UInt8(9)),
                ]),
                CborValue::Array(vec![
                    CborValue::Unsigned(CborUnsignedInt::UInt8(10)),
                    CborValue::Unsigned(CborUnsignedInt::UInt8(11)),
                ]),
            ])
        );
    }

    #[test]
    fn decodes_array_with_nested_map() {
        let cbor_hex = "826161a161626163";
        let cbor = hex_decode(cbor_hex);

        let result = parse_cbor(cbor.as_slice()).unwrap();

        assert_eq!(
            result,
            CborValue::Array(vec![
                CborValue::ByteString(Vec::from("a")),
                CborValue::Map(HashMap::from([(
                    String::from("b"),
                    CborValue::ByteString(Vec::from("c"))
                )])),
            ])
        );
    }

    #[test]
    fn decodes_map_with_nested_array() {
        let cbor_hex = "A26161076162820809";
        let cbor = hex_decode(cbor_hex);

        let result = parse_cbor(cbor.as_slice()).unwrap();

        assert_eq!(
            result,
            CborValue::Map(HashMap::from([
                (
                    String::from("a"),
                    CborValue::Unsigned(CborUnsignedInt::UInt8(7))
                ),
                (
                    String::from("b"),
                    CborValue::Array(vec![
                        CborValue::Unsigned(CborUnsignedInt::UInt8(8)),
                        CborValue::Unsigned(CborUnsignedInt::UInt8(9)),
                    ])
                ),
            ]))
        )
    }

    #[test]
    fn can_parse_cbor_principals_array() {
        let expected_cbor = vec![(
            Principal::from_slice("rdmx6-jaaaa-aaaaa-aaadq-cai".as_bytes()),
            Principal::from_slice("rdmx6-jaaaa-aaaaa-aaadq-cai".as_bytes()),
        )];

        assert_eq!(
            parse_cbor_principals_array(&cbor_encode(&expected_cbor)).unwrap(),
            vec![(
                Principal::from_slice("rdmx6-jaaaa-aaaaa-aaadq-cai".as_bytes()),
                Principal::from_slice("rdmx6-jaaaa-aaaaa-aaadq-cai".as_bytes())
            )],
        )
    }

    #[test]
    fn fails_to_parse_cbor_principals_array() {
        let expected_cbor = vec![(
            "rdmx6-jaaaa-aaaaa-aaadq-cai".as_bytes(),
            "rdmx6-jaaaa-aaaaa-aaadq-cai".as_bytes(),
        )];

        assert!(matches!(
            parse_cbor_principals_array(&cbor_encode(&expected_cbor)).err(),
            Some(CborError::MalformedCborCanisterRanges),
        ));
    }
}
