use crate::cbor::{parse_cbor, CborValue};
use crate::error::ResponseVerificationError;
use crate::hash_tree::parsed_cbor_to_tree;
use ic_certification::{Certificate, Delegation};

pub trait CertificateToCbor<'a> {
    fn from_cbor(cbor: Vec<u8>) -> Result<Certificate<'a>, ResponseVerificationError>;
}

impl<'a> CertificateToCbor<'a> for Certificate<'a> {
    fn from_cbor(cbor: Vec<u8>) -> Result<Certificate<'a>, ResponseVerificationError> {
        let parsed_cbor =
            parse_cbor(&cbor).map_err(|e| ResponseVerificationError::InvalidCbor(e.to_string()))?;

        parsed_cbor_to_certificate(parsed_cbor)
    }
}

fn parsed_cbor_to_certificate<'a>(
    parsed_cbor: CborValue,
) -> Result<Certificate<'a>, ResponseVerificationError> {
    let CborValue::Map(map) = parsed_cbor else {
        return Err(ResponseVerificationError::InvalidCertificate(
            "Expected Map when parsing Certificate Cbor".into()
        ));
    };

    let Some(tree_cbor) = map.get("tree") else {
        return Err(ResponseVerificationError::InvalidCertificate(
            "Expected Tree when parsing Certificate Cbor".into()
        ));
    };

    let tree = parsed_cbor_to_tree(tree_cbor)?;

    let signature = if let Some(CborValue::ByteString(signature)) = map.get("signature") {
        signature.to_owned()
    } else {
        return Err(ResponseVerificationError::InvalidCertificate(
            "Expected Signature when parsing Certificate Cbor".into(),
        ));
    };

    let delegation = if let Some(CborValue::Map(delegation_map)) = map.get("delegation") {
        let Some(CborValue::ByteString(subnet_id)) = delegation_map.get("subnet_id") else {
            return Err(ResponseVerificationError::InvalidCertificate(
                "Expected Delegation Map to contain a Subnet ID when parsing Certificate Cbor".into()
            ));
        };

        let Some(CborValue::ByteString(certificate)) = delegation_map.get("certificate") else {
            return Err(ResponseVerificationError::InvalidCertificate(
                "Expected Delegation Map to contain a Certificate when parsing Certificate Cbor".into()
            ));
        };

        Some(Delegation {
            subnet_id: subnet_id.to_owned(),
            certificate: certificate.to_owned(),
        })
    } else {
        None
    };

    Ok(Certificate {
        tree,
        signature,
        delegation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_certification::{
        hash_tree::{empty, fork, label, leaf},
        HashTree,
    };

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
            Certificate::from_cbor(cbor).expect("Failed to decode certificate from cbor");

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
            Certificate::from_cbor(cbor).expect("Failed to decode certificate from cbor");

        assert_eq!(certificate, original_certificate);
    }
}
