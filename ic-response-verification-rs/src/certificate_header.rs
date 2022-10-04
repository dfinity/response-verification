#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

use crate::{certificate_header_field::CertificateHeaderField, warn};

#[derive(Debug)]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(getter_with_clone))]
pub struct CertificateHeader {
    pub certificate: Option<Vec<u8>>,
    pub tree: Option<Vec<u8>>,
}

impl CertificateHeader {
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

    fn create_header_field(name: &str, value: &str) -> String {
        let base64_value = base64::encode(value);

        format!("{}=:{}:", name, base64_value)
    }

    #[test]
    fn certificate_header_parses_valid_header() {
        let certificate = "Hello Certificate!";
        let tree = "Hello Tree!";
        let header = vec![
            create_header_field("certificate", certificate),
            create_header_field("tree", tree),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(
            certificate_header
                .certificate
                .expect("CertificateHeader did not correctly parse the certificate"),
            certificate.as_bytes()
        );
        assert_eq!(
            certificate_header
                .tree
                .expect("CertificateHeader did not correctly parse the tree"),
            tree.as_bytes()
        );
    }

    #[test]
    fn certificate_header_parses_valid_header_empty_values() {
        let certificate = "";
        let tree = "";
        let header_fields = vec![
            create_header_field("certificate", certificate),
            create_header_field("tree", tree),
        ];
        let header = header_fields.join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(
            certificate_header
                .certificate
                .expect("CertificateHeader did not correctly parse the certificate"),
            certificate.as_bytes()
        );
        assert_eq!(
            certificate_header
                .tree
                .expect("CertificateHeader did not correctly parse the tree"),
            tree.as_bytes()
        );
    }

    #[test]
    fn certificate_header_ignores_extranous_fields() {
        let certificate = "Hello Certificate!";
        let tree = "Hello Tree!";
        let header_fields = vec![
            create_header_field("certificate", certificate),
            create_header_field("tree", tree),
            create_header_field("garbage", "asdhlasjdasdoou"),
        ];
        let header = header_fields.join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(
            certificate_header
                .certificate
                .expect("CertificateHeader did not correctly parse the certificate"),
            certificate.as_bytes()
        );
        assert_eq!(
            certificate_header
                .tree
                .expect("CertificateHeader did not correctly parse the tree"),
            tree.as_bytes()
        );
    }

    #[test]
    fn certificate_header_handles_missing_tree() {
        let certificate = "Hello Certificate!";
        let header_fields = vec![create_header_field("certificate", certificate)];
        let header = header_fields.join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(
            certificate_header
                .certificate
                .expect("CertificateHeader did not correctly parse the certificate"),
            certificate.as_bytes()
        );
        assert_eq!(certificate_header.tree.is_none(), true);
    }

    #[test]
    fn certificate_header_handles_missing_certificate() {
        let tree = "Hello Tree!";
        let header_fields = vec![create_header_field("tree", tree)];
        let header = header_fields.join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(certificate_header.certificate.is_none(), true);
        assert_eq!(
            certificate_header
                .tree
                .expect("CertificateHeader did not correctly parse the tree"),
            tree.as_bytes()
        );
    }

    #[test]
    fn certificate_header_handles_duplicate_fields() {
        let certificate = "Hello Certificate!";
        let tree = "Hello Tree!";
        let second_certificate = "Goodbye Certificate!";
        let second_tree = "Goodbye tree!";
        let header_fields = vec![
            create_header_field("certificate", certificate),
            create_header_field("certificate", second_certificate),
            create_header_field("tree", tree),
            create_header_field("tree", second_tree),
        ];
        let header = header_fields.join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert_eq!(
            certificate_header
                .certificate
                .expect("CertificateHeader did not correctly parse the certificate"),
            certificate.as_bytes()
        );
        assert_eq!(
            certificate_header
                .tree
                .expect("CertificateHeader did not correctly parse the tree"),
            tree.as_bytes()
        );
    }
}
