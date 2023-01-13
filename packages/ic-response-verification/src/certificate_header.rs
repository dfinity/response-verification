use crate::{certificate_header_field::CertificateHeaderField, error, warn};

/// Parsed `Ic-Certificate` header, containing a certificate and tree.
#[derive(Debug)]
pub struct CertificateHeader {
    pub certificate: Option<Vec<u8>>,
    pub tree: Option<Vec<u8>>,
    pub version: Option<u8>,
    pub expr_path: Option<Vec<u8>>,
}

impl CertificateHeader {
    /// Parses the given header and returns a new CertificateHeader.
    pub fn from(header_value: &str) -> CertificateHeader {
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
                            None => decode_base64_header(name, value),
                            Some(existing_certificate) => {
                                warn!("Found duplicate certificate field in certificate header, ignoring...");

                                Some(existing_certificate)
                            }
                        };
                    }
                    "tree" => {
                        certificate_header.tree = match certificate_header.tree {
                            None => decode_base64_header(name, value),
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
                            None => parse_int_header(name, value),
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
                            None => decode_base64_header(name, value),
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

        return certificate_header;
    }
}

fn decode_base64_header(name: &str, value: &str) -> Option<Vec<u8>> {
    match base64::decode(value) {
        Ok(value) => Some(value),
        Err(e) => {
            error!(
                "Error base64 decoding {} field of certificate header: {}",
                name, e
            );

            None
        }
    }
}

fn parse_int_header(name: &str, value: &str) -> Option<u8> {
    match value.parse::<u8>() {
        Ok(value) => Some(value),
        Err(e) => {
            error!(
                "Error parsing {} field of certificate header into uint8: {}",
                name, e
            );

            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_utils::{
        cbor_encode, create_certificate, create_encoded_header_field, create_header_field,
        create_tree,
    };

    #[test]
    fn certificate_header_parses_valid_header() {
        let certificate = cbor_encode(&create_certificate(None));
        let tree = cbor_encode(&create_tree(None));
        let version = 2u8;
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = vec![
            create_encoded_header_field("certificate", &certificate),
            create_encoded_header_field("tree", &tree),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", &expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(certificate_header.certificate.unwrap(), certificate);
        assert_eq!(certificate_header.tree.unwrap(), tree);
        assert_eq!(certificate_header.version.unwrap(), version);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }

    #[test]
    fn certificate_header_parses_valid_header_empty_values() {
        let header = vec![
            create_encoded_header_field("certificate", ""),
            create_encoded_header_field("tree", ""),
            create_encoded_header_field("version", ""),
            create_encoded_header_field("expr_path", ""),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert!(certificate_header.certificate.unwrap().is_empty());
        assert!(certificate_header.tree.unwrap().is_empty());
        assert!(certificate_header.version.is_none());
        assert!(certificate_header.expr_path.unwrap().is_empty());
    }

    #[test]
    fn certificate_header_ignores_extraneous_fields() {
        let certificate = cbor_encode(&create_certificate(None));
        let tree = cbor_encode(&create_tree(None));
        let version = 2u8;
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = vec![
            create_encoded_header_field("certificate", &certificate),
            create_encoded_header_field("tree", &tree),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", &expr_path),
            create_encoded_header_field("garbage", "asdhlasjdasdoou"),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

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
        let header = vec![
            create_encoded_header_field("certificate", &certificate),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", &expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

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
        let header = vec![
            create_encoded_header_field("tree", &tree),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", &expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert!(certificate_header.certificate.is_none());
        assert_eq!(certificate_header.tree.unwrap(), tree);
    }

    #[test]
    fn certificate_header_handles_missing_version() {
        let certificate = cbor_encode(&create_certificate(None));
        let tree = cbor_encode(&create_tree(None));
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = vec![
            create_encoded_header_field("certificate", &certificate),
            create_encoded_header_field("tree", &tree),
            create_encoded_header_field("expr_path", &expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

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
        let header = vec![
            create_encoded_header_field("certificate", &certificate),
            create_encoded_header_field("tree", &tree),
            create_header_field("version", &version.to_string()),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

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

        let header = vec![
            create_encoded_header_field("certificate", &certificate),
            create_encoded_header_field("certificate", second_certificate),
            create_encoded_header_field("tree", &tree),
            create_encoded_header_field("tree", second_tree),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", &expr_path),
            create_encoded_header_field("version", &second_version.to_string()),
            create_encoded_header_field("expr_path", &second_expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(certificate_header.certificate.unwrap(), certificate);
        assert_eq!(certificate_header.tree.unwrap(), tree.as_slice());
        assert_eq!(certificate_header.version.unwrap(), version);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }
}
