use crate::error;

/// Parsed key, value pair for an `Ic-Certificate` header field.
#[derive(Debug)]
pub struct CertificateHeaderField(pub String, pub Vec<u8>);

impl CertificateHeaderField {
    /// Parses the given header field string and returns a new CertificateHeaderField.
    ///
    /// ```
    /// let certificate_header_field = CertificateHeaderField::from("certificate=:SGVsbG8gQ2VydGlmaWNhdGUh:");
    /// ```
    pub fn from(header_field: &str) -> Option<CertificateHeaderField> {
        if let Some((name, encoded_value)) = extract_header_field(header_field.trim()) {
            if let Some(value) = decode_header_field_value(&name, &encoded_value) {
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

fn extract_header_field(header_field: &str) -> Option<(String, String)> {
    #[cfg(target_arch = "wasm32")]
    if let Some(values) = js_sys::RegExp::new("^(.*)=:(.*):$", "")
        .exec(header_field)
        .map(|x| x.to_vec())
        .map(|x| {
            x.into_iter()
                .filter_map(|y| y.as_string())
                .collect::<Vec<String>>()
        })
    {
        return Some((values[1].clone(), values[2].clone()));
    }

    #[cfg(not(target_arch = "wasm32"))]
    if let Some((_whole, name, encoded_value)) =
        lazy_regex::regex_captures!("^(.*)=:(.*):$", header_field)
    {
        return Some((name.to_string(), encoded_value.to_string()));
    }

    return None;
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
