use lazy_regex::regex_captures;

use crate::error;

#[derive(Debug)]
pub struct CertificateHeaderField<'a>(pub &'a str, pub Vec<u8>);

impl<'a> CertificateHeaderField<'a> {
    pub fn from(header_field: &'a str) -> Option<CertificateHeaderField<'a>> {
        if let Some((_, name, encoded_value)) =
            regex_captures!("^(.*)=:(.*):$", header_field.trim())
        {
            if let Some(value) = decode_header_field_value(name, encoded_value) {
                return Some(CertificateHeaderField(name, value));
            }
        }

        return None;
    }
}

fn decode_header_field_value(name: &str, value: &str) -> Option<Vec<u8>> {
    match base64::decode(value) {
        Ok(value) => Some(value),
        Err(e) => {
            error!(
                "Error decoding value of {} field in certificate header: {}",
                name, e
            );

            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_header_field(name: &str, value: &str) -> String {
        let base64_value = base64::encode(value);

        format!("{}=:{}:", name, base64_value)
    }

    #[test]
    fn certificate_header_field_parses_valid_field() {
        let name = "message";
        let value = "Hello World!";
        let header_field = create_header_field(name, value);

        let CertificateHeaderField(result_name, result_value) =
            CertificateHeaderField::from(header_field.as_str())
                .expect("CertificateHeaderField not parsed correctly");

        assert_eq!(result_name, name);
        assert_eq!(result_value, value.as_bytes());
    }

    #[test]
    fn certificate_header_field_parses_valid_field_with_empty_values() {
        let header_field = create_header_field("", "");

        let CertificateHeaderField(result_name, result_value) =
            CertificateHeaderField::from(header_field.as_str())
                .expect("CertificateHeaderField not parsed correctly");

        assert_eq!(result_name, "");
        assert_eq!(result_value.is_empty(), true);
    }

    #[test]
    fn certificate_header_field_does_not_parse_plaintext_value() {
        let name = "message";
        let value = "hello_world";

        let header_field = format!("{}=:{}:", name, value);

        let result = CertificateHeaderField::from(header_field.as_str());

        assert_eq!(result.is_none(), true);
    }

    #[test]
    fn certificate_header_field_does_not_parse_empty_field() {
        let result = CertificateHeaderField::from("");

        assert_eq!(result.is_none(), true);
    }

    #[test]
    fn certificate_header_field_does_not_parse_invalid_field() {
        let name = "message";
        let value = "hello_world";

        let base64_value = base64::encode(value);
        let header_field = format!("{}:{}", name, base64_value);

        let result = CertificateHeaderField::from(header_field.as_str());

        assert_eq!(result.is_none(), true);
    }
}
