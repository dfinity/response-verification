use super::{certificate_header_field::CertificateHeaderField, MIN_VERIFICATION_VERSION};
use crate::{
    base64::BASE64,
    error::{ResponseVerificationError, ResponseVerificationResult},
};
use base64::Engine as _;
use ic_cbor::{parse_cbor_string_array, CertificateToCbor, HashTreeToCbor};
use ic_certification::{Certificate, HashTree};
use log::warn;

/// Parsed `Ic-Certificate` header, containing a certificate and tree.
#[derive(Debug, PartialEq, Eq)]
pub struct CertificateHeader {
    /// The [`Certificate`](https://internetcomputer.org/docs/current/references/ic-interface-spec/#certificate) contained in the header.
    pub certificate: Certificate,

    /// A pruned hash tree containing a witness that certifies the response for the given certificate.
    pub tree: HashTree,

    /// The version of the verification algorithm that should be used to verify the response.
    pub version: u8,

    /// The path in the `HashTree` pointing to the CEL expression used to calulate the response's certification.
    /// This field is not present for response verification v1.
    pub expr_path: Option<Vec<String>>,
}

impl CertificateHeader {
    /// Parses the given header and returns a new CertificateHeader.
    pub fn from(header_value: &str) -> ResponseVerificationResult<CertificateHeader> {
        let mut certificate = None;
        let mut tree = None;
        let mut version = None;
        let mut expr_path = None;

        for field in header_value.split(',') {
            if let Some(CertificateHeaderField(name, value)) = CertificateHeaderField::from(field) {
                match name {
                    "certificate" => {
                        certificate = match certificate {
                            None => {
                                let certificate_bytes = decode_base64_header(value)?;
                                let certificate = Certificate::from_cbor(&certificate_bytes)?;

                                Some(certificate)
                            }
                            Some(existing_certificate) => {
                                warn!("Found duplicate certificate field in certificate header, ignoring...");

                                Some(existing_certificate)
                            }
                        };
                    }
                    "tree" => {
                        tree = match tree {
                            None => {
                                let tree_bytes = decode_base64_header(value)?;
                                let tree = HashTree::from_cbor(&tree_bytes)?;

                                Some(tree)
                            }
                            Some(existing_tree) => {
                                warn!(
                                    "Found duplicate tree field in certificate header, ignoring..."
                                );

                                Some(existing_tree)
                            }
                        };
                    }
                    "version" => {
                        version = match version {
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
                        expr_path = match expr_path {
                            None => {
                                let expr_path_bytes = decode_base64_header(value)?;
                                let expr_path = parse_cbor_string_array(&expr_path_bytes)?;

                                Some(expr_path)
                            }
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

        let certificate = certificate.ok_or(ResponseVerificationError::HeaderMissingCertificate)?;
        let tree = tree.ok_or(ResponseVerificationError::HeaderMissingTree)?;
        let version = version.unwrap_or(MIN_VERIFICATION_VERSION);

        Ok(CertificateHeader {
            certificate,
            tree,
            version,
            expr_path,
        })
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
        let certificate = create_certificate(None);
        let tree = create_tree(None);
        let version = 2u8;
        let expr_path = vec!["/", "assets", "img.jpg"];
        let header = [
            create_encoded_header_field("certificate", cbor_encode(&certificate)),
            create_encoded_header_field("tree", cbor_encode(&tree)),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", cbor_encode(&expr_path)),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate, certificate);
        assert_eq!(certificate_header.tree, tree);
        assert_eq!(certificate_header.version, version);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }

    #[test]
    fn certificate_header_parses_valid_header_with_unpadded_base64() {
        let certificate = create_certificate(None);
        let tree = create_tree(None);
        let version = 2u8;
        let expr_path = vec!["/", "assets", "img.jpg"];
        let header = [
            create_header_field(
                "certificate",
                &base64_encode_no_padding(&cbor_encode(&certificate)),
            ),
            create_header_field("tree", &base64_encode_no_padding(&cbor_encode(&tree))),
            create_header_field("version", &version.to_string()),
            create_header_field(
                "expr_path",
                &base64_encode_no_padding(&cbor_encode(&expr_path)),
            ),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate, certificate);
        assert_eq!(certificate_header.tree, tree);
        assert_eq!(certificate_header.version, version);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }

    #[test]
    fn certificate_header_ignores_extraneous_fields() {
        let certificate = create_certificate(None);
        let tree = create_tree(None);
        let version = 2u8;
        let expr_path = vec!["/", "assets", "img.jpg"];
        let header = [
            create_encoded_header_field("certificate", cbor_encode(&certificate)),
            create_encoded_header_field("tree", cbor_encode(&tree)),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", cbor_encode(&expr_path)),
            create_encoded_header_field("garbage", "asdhlasjdasdoou"),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate, certificate);
        assert_eq!(certificate_header.tree, tree);
        assert_eq!(certificate_header.version, version);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }

    #[test]
    fn certificate_header_throws_with_missing_tree() {
        let certificate = create_certificate(None);
        let version = 2u8;
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = [
            create_encoded_header_field("certificate", cbor_encode(&certificate)),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert!(matches!(
            certificate_header,
            Err(ResponseVerificationError::HeaderMissingTree)
        ));
    }

    #[test]
    fn certificate_header_throws_with_empty_tree() {
        let certificate = create_certificate(None);
        let version = 2u8;
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = [
            create_encoded_header_field("certificate", cbor_encode(&certificate)),
            create_encoded_header_field("tree", ""),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", expr_path),
        ]
        .join(",");

        let result = CertificateHeader::from(header.as_str());

        assert!(matches!(
            result,
            Err(ResponseVerificationError::HeaderMissingTree)
        ));
    }

    #[test]
    fn certificate_header_throws_with_missing_certificate() {
        let tree = create_tree(None);
        let version = 2u8;
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = [
            create_encoded_header_field("tree", cbor_encode(&tree)),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str());

        assert!(matches!(
            certificate_header,
            Err(ResponseVerificationError::HeaderMissingCertificate)
        ));
    }

    #[test]
    fn certificate_header_throws_with_empty_certificate() {
        let tree = create_tree(None);
        let version = 2u8;
        let expr_path = cbor_encode(&vec!["/", "assets", "img.jpg"]);
        let header = [
            create_encoded_header_field("certificate", ""),
            create_encoded_header_field("tree", cbor_encode(&tree)),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", expr_path),
        ]
        .join(",");

        let result = CertificateHeader::from(header.as_str());

        assert!(matches!(
            result,
            Err(ResponseVerificationError::HeaderMissingCertificate)
        ));
    }

    #[test]
    fn certificate_header_handles_missing_version() {
        let certificate = create_certificate(None);
        let tree = create_tree(None);
        let expr_path = vec!["/", "assets", "img.jpg"];
        let header = [
            create_encoded_header_field("certificate", cbor_encode(&certificate)),
            create_encoded_header_field("tree", cbor_encode(&tree)),
            create_encoded_header_field("expr_path", cbor_encode(&&expr_path)),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate, certificate);
        assert_eq!(certificate_header.tree, tree);
        assert_eq!(certificate_header.version, MIN_VERIFICATION_VERSION);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }

    #[test]
    fn certificate_header_handles_empty_version() {
        let certificate = create_certificate(None);
        let tree = create_tree(None);
        let expr_path = vec!["/", "assets", "img.jpg"];
        let header = [
            create_encoded_header_field("certificate", cbor_encode(&certificate)),
            create_encoded_header_field("tree", cbor_encode(&tree)),
            create_encoded_header_field("version", ""),
            create_encoded_header_field("expr_path", cbor_encode(&expr_path)),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate, certificate);
        assert_eq!(certificate_header.tree, tree);
        assert_eq!(certificate_header.version, MIN_VERIFICATION_VERSION);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }

    #[test]
    fn certificate_header_handles_missing_expr_path() {
        let certificate = create_certificate(None);
        let tree = create_tree(None);
        let version = 2u8;
        let header = [
            create_encoded_header_field("certificate", cbor_encode(&certificate)),
            create_encoded_header_field("tree", cbor_encode(&tree)),
            create_header_field("version", &version.to_string()),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate, certificate);
        assert_eq!(certificate_header.tree, tree);
        assert_eq!(certificate_header.version, version);
        assert!(certificate_header.expr_path.is_none());
    }

    #[test]
    fn certificate_header_handles_empty_expr_path() {
        let certificate = create_certificate(None);
        let tree = create_tree(None);
        let version = 2u8;
        let header = [
            create_encoded_header_field("certificate", cbor_encode(&certificate)),
            create_encoded_header_field("tree", cbor_encode(&tree)),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", ""),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate, certificate);
        assert_eq!(certificate_header.tree, tree);
        assert_eq!(certificate_header.version, version);
        assert!(certificate_header.expr_path.is_none());
    }

    #[test]
    fn certificate_header_ignores_duplicate_fields() {
        let certificate = create_certificate(None);
        let tree = create_tree(None);
        let version = 2u8;
        let expr_path = vec!["/", "assets", "img.jpg"];

        let second_certificate = "Goodbye Certificate!";
        let second_tree = "Goodbye tree!";
        let second_version = 3u8;
        let second_expr_path = "Goodbye expr_path!";

        let header = [
            create_encoded_header_field("certificate", cbor_encode(&certificate)),
            create_encoded_header_field("certificate", second_certificate),
            create_encoded_header_field("tree", cbor_encode(&tree)),
            create_encoded_header_field("tree", second_tree),
            create_header_field("version", &version.to_string()),
            create_encoded_header_field("expr_path", cbor_encode(&expr_path)),
            create_encoded_header_field("version", second_version.to_string()),
            create_encoded_header_field("expr_path", second_expr_path),
        ]
        .join(",");

        let certificate_header = CertificateHeader::from(header.as_str()).unwrap();

        assert_eq!(certificate_header.certificate, certificate);
        assert_eq!(certificate_header.tree, tree);
        assert_eq!(certificate_header.version, version);
        assert_eq!(certificate_header.expr_path.unwrap(), expr_path);
    }
}
