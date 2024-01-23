use super::certificate_header_field::CertificateHeaderField;
use crate::{
    base64::BASE64,
    error::{ResponseVerificationError, ResponseVerificationResult},
};
use base64::Engine as _;
use log::warn;

/// Parsed `Ic-Certificate` header, containing a certificate and tree.
#[derive(Debug, PartialEq, Eq)]
pub struct CertificateHeader {
    pub certificate: Option<Vec<u8>>,
    pub tree: Option<Vec<u8>>,
    pub version: Option<u8>,
    pub expr_path: Option<Vec<u8>>,
}

impl CertificateHeader {
    /// Parses the given header and returns a new CertificateHeader.
    pub fn from(header_value: &str) -> ResponseVerificationResult<CertificateHeader> {
        let mut certificate_header = CertificateHeader {
            certificate: None,
            tree: None,
            version: None,
            expr_path: None,
        };

        for field in header_value.split(',') {
            if let Some(CertificateHeaderField(name, value)) = CertificateHeaderField::from(field) {
                match name {
                    "certificate" => {
                        certificate_header.certificate = match certificate_header.certificate {
                            None => Some(decode_base64_header(value)?),
                            Some(existing_certificate) => {
                                warn!("Found duplicate certificate field in certificate header, ignoring...");

                                Some(existing_certificate)
                            }
                        };
                    }
                    "tree" => {
                        certificate_header.tree = match certificate_header.tree {
                            None => Some(decode_base64_header(value)?),
                            Some(existing_tree) => {
                                warn!(
                                    "Found duplicate tree field in certificate header, ignoring..."
                                );

                                Some(existing_tree)
                            }
                        };
                    }
                    "version" => {
                        certificate_header.version = match certificate_header.version {
                            None => Some(parse_int_header(value)?),
                            Some(existing_version) => {
                                warn!(
                                    "Found duplicate version field in certificate header, ignoring..."
                                );

                                Some(existing_version)
                            }
                        };
                    }
                    "expr_path" => {
                        certificate_header.expr_path = match certificate_header.expr_path {
                            None => Some(decode_base64_header(value)?),
                            Some(existing_expr_path) => {
                                warn!(
                                    "Found duplicate expr_path field in certificate header, ignoring..."
                                );

                                Some(existing_expr_path)
                            }
                        };
                    }
                    _ => {}
                }
            }
        }

        Ok(certificate_header)
    }
}

fn decode_base64_header(value: &str) -> ResponseVerificationResult<Vec<u8>> {
    BASE64
        .decode(value)
        .map_err(ResponseVerificationError::Base64DecodingError)
}

fn parse_int_header(value: &str) -> ResponseVerificationResult<u8> {
    value
        .parse::<u8>()
        .map_err(ResponseVerificationError::ParseIntError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{create_encoded_header_field, create_header_field, create_tree};
    use ic_response_verification_test_utils::{cbor_encode, create_certificate};

    fn base64_encode_no_padding(data: &[u8]) -> String {
        use base64::engine::general_purpose;
        general_purpose::STANDARD_NO_PAD.encode(data)
    }

    #[test]
    fn certificate_header_parses_valid_header() {
        let certificate = cbor_encode(&create_certificate(None));
        let tree = cbor_encode(&create_tree(None));
        let version = 2u8;
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = [
            create_encoded_header_field("certificate", &certificate),
            create_encoded_header_field("tree", &tree),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", &expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate.unwrap(), certificate);
        assert_eq!(certificate_header.tree.unwrap(), tree);
        assert_eq!(certificate_header.version.unwrap(), version);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }

    #[test]
    fn certificate_header_parsed_valid_header_with_unpadded_base64() {
        let certificate = cbor_encode(&create_certificate(None));
        let tree = cbor_encode(&create_tree(None));
        let version = 2u8;
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = [
            create_header_field("certificate", &base64_encode_no_padding(&certificate)),
            create_header_field("tree", &base64_encode_no_padding(&tree)),
            create_header_field("version", &version.to_string()),
            create_header_field("expr_path", &base64_encode_no_padding(&expr_path)),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate.unwrap(), certificate);
        assert_eq!(certificate_header.tree.unwrap(), tree);
        assert_eq!(certificate_header.version.unwrap(), version);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }

    #[test]
    fn certificate_header_parses_valid_header_empty_values() {
        let header = [
            create_encoded_header_field("certificate", ""),
            create_encoded_header_field("tree", ""),
            create_encoded_header_field("version", ""),
            create_encoded_header_field("expr_path", ""),
        ]
        .join(",");

        let result = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(
            result,
            CertificateHeader {
                certificate: None,
                expr_path: None,
                tree: None,
                version: None,
            }
        );
    }

    #[test]
    fn certificate_header_ignores_extraneous_fields() {
        let certificate = cbor_encode(&create_certificate(None));
        let tree = cbor_encode(&create_tree(None));
        let version = 2u8;
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = [
            create_encoded_header_field("certificate", &certificate),
            create_encoded_header_field("tree", &tree),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", &expr_path),
            create_encoded_header_field("garbage", "asdhlasjdasdoou"),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate.unwrap(), certificate);
        assert_eq!(certificate_header.tree.unwrap(), tree);
        assert_eq!(certificate_header.version.unwrap(), version);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }

    #[test]
    fn certificate_header_handles_missing_tree() {
        let certificate = cbor_encode(&create_certificate(None));
        let version = 2u8;
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = [
            create_encoded_header_field("certificate", &certificate),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", &expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate.unwrap(), certificate);
        assert!(certificate_header.tree.is_none());
        assert_eq!(certificate_header.version.unwrap(), version);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }

    #[test]
    fn certificate_header_handles_missing_certificate() {
        let tree = cbor_encode(&create_tree(None));
        let version = 2u8;
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = [
            create_encoded_header_field("tree", &tree),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert!(certificate_header.certificate.is_none());
        assert_eq!(certificate_header.tree.unwrap(), tree);
    }

    #[test]
    fn certificate_header_handles_missing_version() {
        let certificate = cbor_encode(&create_certificate(None));
        let tree = cbor_encode(&create_tree(None));
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = [
            create_encoded_header_field("certificate", &certificate),
            create_encoded_header_field("tree", &tree),
            create_encoded_header_field("expr_path", &expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate.unwrap(), certificate);
        assert_eq!(certificate_header.tree.unwrap(), tree);
        assert!(certificate_header.version.is_none());
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }

    #[test]
    fn certificate_header_handles_missing_expr_path() {
        let certificate = cbor_encode(&create_certificate(None));
        let tree = cbor_encode(&create_tree(None));
        let version = 2u8;
        let header = [
            create_encoded_header_field("certificate", &certificate),
            create_encoded_header_field("tree", &tree),
            create_header_field("version", &version.to_string()),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate.unwrap(), certificate);
        assert_eq!(certificate_header.tree.unwrap(), tree);
        assert_eq!(certificate_header.version.unwrap(), version);
        assert!(certificate_header.expr_path.is_none());
    }

    #[test]
    fn certificate_header_ignores_duplicate_fields() {
        let certificate = cbor_encode(&create_certificate(None));
        let tree = cbor_encode(&create_tree(None));
        let version = 2u8;
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);

        let second_certificate = "Goodbye Certificate!";
        let second_tree = "Goodbye tree!";
        let second_version = 3u8;
        let second_expr_path = "Goodbye expr_path!";

        let header = [
            create_encoded_header_field("certificate", &certificate),
            create_encoded_header_field("certificate", second_certificate),
            create_encoded_header_field("tree", &tree),
            create_encoded_header_field("tree", second_tree),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", &expr_path),
            create_encoded_header_field("version", second_version.to_string()),
            create_encoded_header_field("expr_path", second_expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate.unwrap(), certificate);
        assert_eq!(certificate_header.tree.unwrap(), tree.as_slice());
        assert_eq!(certificate_header.version.unwrap(), version);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }
}
