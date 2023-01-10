use crate::{certificate_header_field::CertificateHeaderField, warn};

/// Parsed `Ic-Certificate` header, containing a certificate and tree.
#[derive(Debug)]
pub struct CertificateHeader {
    pub certificate: Option<Vec<u8>>,
    pub tree: Option<Vec<u8>>,
}

impl CertificateHeader {
    /// Parses the given header and returns a new CertificateHeader.
    pub fn from(header_value: &str) -> CertificateHeader {
        let mut certificate_header = CertificateHeader {
            certificate: None,
            tree: None,
        };

        for field in header_value.split(',') {
            if let Some(CertificateHeaderField(name, value)) = CertificateHeaderField::from(field) {
                match name {
                    "certificate" => {
                        certificate_header.certificate = match certificate_header.certificate {
                            None => Some(value),
                            Some(existing_certificate) => {
                                warn!("Found duplicate certificate field in certificate header, ignoring...");

                                Some(existing_certificate)
                            }
                        };
                    }
                    "tree" => {
                        certificate_header.tree = match certificate_header.tree {
                            None => Some(value),
                            Some(existing_tree) => {
                                warn!(
                                    "Found duplicate tree field in certificate header, ignoring..."
                                );

                                Some(existing_tree)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_utils::{
        cbor_encode, create_certificate, create_header_field, create_tree,
    };

    #[test]
    fn certificate_header_parses_valid_header() {
        let certificate = cbor_encode(&create_certificate(None));
        let tree = cbor_encode(&create_tree(None));
        let header = vec![
            create_header_field("certificate", &certificate),
            create_header_field("tree", &tree),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(
            certificate_header.certificate.unwrap(),
            certificate.as_slice()
        );
        assert_eq!(certificate_header.tree.unwrap(), tree.as_slice());
    }

    #[test]
    fn certificate_header_parses_valid_header_empty_values() {
        let certificate = "";
        let tree = "";
        let header = vec![
            create_header_field("certificate", certificate),
            create_header_field("tree", tree),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(
            certificate_header.certificate.unwrap(),
            certificate.as_bytes()
        );
        assert_eq!(certificate_header.tree.unwrap(), tree.as_bytes());
    }

    #[test]
    fn certificate_header_ignores_extraneous_fields() {
        let certificate = cbor_encode(&create_certificate(None));
        let tree = cbor_encode(&create_tree(None));
        let header = vec![
            create_header_field("certificate", &certificate),
            create_header_field("tree", &tree),
            create_header_field("garbage", "asdhlasjdasdoou"),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(
            certificate_header.certificate.unwrap(),
            certificate.as_slice()
        );
        assert_eq!(certificate_header.tree.unwrap(), tree.as_slice());
    }

    #[test]
    fn certificate_header_handles_missing_tree() {
        let certificate = "Hello Certificate!";
        let header = vec![create_header_field("certificate", certificate)].join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(
            certificate_header.certificate.unwrap(),
            certificate.as_bytes()
        );
        assert_eq!(certificate_header.tree.is_none(), true);
    }

    #[test]
    fn certificate_header_handles_missing_certificate() {
        let tree = "Hello Tree!";
        let header = vec![create_header_field("tree", tree)].join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(certificate_header.certificate.is_none(), true);
        assert_eq!(certificate_header.tree.unwrap(), tree.as_bytes());
    }

    #[test]
    fn certificate_header_handles_duplicate_fields() {
        let certificate = cbor_encode(&create_certificate(None));
        let tree = cbor_encode(&create_tree(None));
        let second_certificate = "Goodbye Certificate!";
        let second_tree = "Goodbye tree!";
        let header = vec![
            create_header_field("certificate", &certificate),
            create_header_field("certificate", second_certificate),
            create_header_field("tree", &tree),
            create_header_field("tree", second_tree),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(
            certificate_header.certificate.unwrap(),
            certificate.as_slice()
        );
        assert_eq!(certificate_header.tree.unwrap(), tree.as_slice());
    }
}
