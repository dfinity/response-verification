use crate::cbor::{parse_cbor, CborValue};
use crate::error::ResponseVerificationError;
use crate::hash_tree::parsed_cbor_to_tree;
use ic_certification::{Certificate, Delegation, HashTree};

pub trait CertificateToCbor {
    fn from_cbor(cbor: &[u8]) -> Result<Certificate, ResponseVerificationError>;
}

impl<'a> CertificateToCbor for Certificate<'a> {
    fn from_cbor(cbor: &[u8]) -> Result<Certificate, ResponseVerificationError> {
        let parsed_cbor =
            parse_cbor(cbor).map_err(|e| ResponseVerificationError::InvalidCbor(e.to_string()))?;

        parsed_cbor_to_certificate(parsed_cbor)
    }
}

fn parsed_cbor_to_certificate<'a>(
    parsed_cbor: CborValue,
) -> Result<Certificate<'a>, ResponseVerificationError> {
    let mut tree: Option<HashTree> = None;
    let mut signature: Option<Vec<u8>> = None;
    let mut delegation: Option<Delegation> = None;

    if let CborValue::Map(map) = parsed_cbor {
        if let Some(tree_cbor) = map.get("tree") {
            let parsed_tree = parsed_cbor_to_tree(tree_cbor)?;
            tree = Some(parsed_tree);
        }

        if let Some(CborValue::ByteString(parsed_signature)) = map.get("signature") {
            signature = Some(parsed_signature.to_owned());
        }

        if let Some(CborValue::Map(parsed_delegation)) = map.get("delegation") {
            if let (
                Some(CborValue::ByteString(subnet_id)),
                Some(CborValue::ByteString(certificate)),
            ) = (
                parsed_delegation.get("subnet_id"),
                parsed_delegation.get("certificate"),
            ) {
                delegation = Some(Delegation {
                    subnet_id: subnet_id.to_owned(),
                    certificate: certificate.to_owned(),
                });
            }
        }
    }

    if let (Some(tree), Some(signature)) = (tree, signature) {
        Ok(Certificate {
            tree,
            signature,
            delegation,
        })
    } else {
        Err(ResponseVerificationError::InvalidCertificate(String::from(
            "Missing tree or signature in Certificate",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_certification::hash_tree::{empty, fork, label, leaf};

    fn create_tree<'a>() -> HashTree<'a> {
        return fork(
            fork(
                label(
                    "a",
                    fork(
                        fork(label("x", leaf(b"hello")), empty()),
                        label("y", leaf(b"world")),
                    ),
                ),
                label("b", leaf(b"good")),
            ),
            fork(label("c", empty()), label("d", leaf(b"morning"))),
        );
    }

    #[test]
    fn deserialize_from_cbor() {
        let tree = create_tree();
        let signature = vec![1, 2, 3, 4, 5, 6];

        let original_certificate = Certificate {
            tree,
            signature,
            delegation: None,
        };

        let cbor = serde_cbor::to_vec(&original_certificate)
            .expect("Failed to encode certificate to cbor");

        let certificate =
            Certificate::from_cbor(&cbor).expect("Failed to decode certificate from cbor");

        assert_eq!(certificate, original_certificate);
    }

    #[test]
    fn deserialize_from_cbor_with_delegation() {
        let tree = create_tree();
        let signature = vec![1, 2, 3, 4, 5, 6];
        let delegation = Delegation {
            subnet_id: vec![7, 8, 9, 10, 11, 12],
            certificate: vec![13, 14, 15, 16, 17, 18],
        };

        let original_certificate = Certificate {
            tree,
            signature,
            delegation: Some(delegation),
        };

        let cbor = serde_cbor::to_vec(&original_certificate)
            .expect("Failed to encode certificate to cbor");

        let certificate =
            Certificate::from_cbor(&cbor).expect("Failed to decode certificate from cbor");

        assert_eq!(certificate, original_certificate);
    }
}
