use nom::{
    bytes::complete::take_while,
    bytes::complete::{tag, take_until},
    character::complete::char,
    combinator::{eof, opt},
    sequence::{delimited, terminated},
    IResult,
};

/// Parsed key, value pair for an `Ic-Certificate` header field.
#[derive(Debug)]
pub struct CertificateHeaderField<'a>(pub &'a str, pub &'a str);

impl<'a> CertificateHeaderField<'a> {
    /// Parses the given header field string and returns a new CertificateHeaderField.
    pub fn from(header_field: &'a str) -> Option<CertificateHeaderField<'a>> {
        extract_header_field(header_field.trim())
            .map(|(name, value)| CertificateHeaderField(name, value))
    }
}

fn extract_header_field(header_field: &str) -> Option<(&str, &str)> {
    fn drop_delimiters(v: char, i: &str) -> IResult<&str, &str> {
        delimited(opt(char(v)), take_while(|e| e != v), opt(char(v)))(i)
    }

    fn until_terminated<'a>(v: &str, i: &'a str) -> IResult<&'a str, &'a str> {
        terminated(take_until(v), tag(v))(i)
    }

    fn extract(i: &str) -> IResult<&str, (&str, &str)> {
        let (i, name) = until_terminated("=", i)?;
        let (i, value) = drop_delimiters(':', i)?;

        eof(i)?;

        Ok((i, (name, value)))
    }

    extract(header_field).ok().and_then(|(_, (name, value))| {
        if name.is_empty() || value.is_empty() {
            None
        } else {
            Some((name, value))
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::create_encoded_header_field;
    use ic_response_verification_test_utils::{base64_encode, cbor_encode, create_certificate};

    #[test]
    fn certificate_header_field_parses_valid_field() {
        let name = "certificate";
        let value = cbor_encode(&create_certificate(None));
        let header_field = create_encoded_header_field(name, &value);

        let CertificateHeaderField(result_name, result_value) =
            CertificateHeaderField::from(header_field.as_str()).unwrap();

        assert_eq!(result_name, name);
        assert_eq!(result_value, base64_encode(&value));
    }

    #[test]
    fn certificate_header_field_parses_valid_field_without_delimiters() {
        let name = "version";
        let value = 2.to_string();
        let header_field = format!("{}={}", name, value);

        let CertificateHeaderField(result_name, result_value) =
            CertificateHeaderField::from(header_field.as_str()).unwrap();

        assert_eq!(result_name, name);
        assert_eq!(result_value, value);
    }

    #[test]
    fn certificate_header_field_parses_valid_field_with_empty_values() {
        let header_field = create_encoded_header_field("", "");

        let result = CertificateHeaderField::from(header_field.as_str());

        assert!(result.is_none());
    }

    #[test]
    fn certificate_header_field_does_not_parse_empty_field() {
        let result = CertificateHeaderField::from("");

        assert!(result.is_none());
    }

    #[test]
    fn certificate_header_field_does_not_parse_invalid_field() {
        let name = "certificate";
        let value = cbor_encode(&create_certificate(None));
        let value = base64_encode(&value);

        let header_field = format!("{}:{}", name, value);

        let result = CertificateHeaderField::from(header_field.as_str());

        assert!(result.is_none());
    }
}
