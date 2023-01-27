use crate::cbor::{hash_tree::parsed_cbor_to_tree, parse_cbor, CborValue};
use crate::error::ResponseVerificationError;
use ic_certification::{Certificate, Delegation};

pub trait CertificateToCbor<'a> {
    fn from_cbor(cbor: &[u8]) -> Result<Certificate<'a>, ResponseVerificationError>;
}

impl<'a> CertificateToCbor<'a> for Certificate<'a> {
    fn from_cbor(cbor: &[u8]) -> Result<Certificate<'a>, ResponseVerificationError> {
        let parsed_cbor = parse_cbor(cbor)
            .map_err(|e| ResponseVerificationError::MalformedCbor(e.to_string()))?;

        parsed_cbor_to_certificate(parsed_cbor)
    }
}

fn parsed_cbor_to_certificate<'a>(
    parsed_cbor: CborValue,
) -> Result<Certificate<'a>, ResponseVerificationError> {
    let CborValue::Map(map) = parsed_cbor else {
        return Err(ResponseVerificationError::MalformedCertificate(
            "Expected Map when parsing Certificate Cbor".into()
        ));
    };

    let Some(tree_cbor) = map.get("tree") else {
        return Err(ResponseVerificationError::MalformedCertificate(
            "Expected Tree when parsing Certificate Cbor".into()
        ));
    };

    let tree = parsed_cbor_to_tree(tree_cbor)?;

    let signature = if let Some(CborValue::ByteString(signature)) = map.get("signature") {
        signature.to_owned()
    } else {
        return Err(ResponseVerificationError::MalformedCertificate(
            "Expected Signature when parsing Certificate Cbor".into(),
        ));
    };

    let delegation = if let Some(CborValue::Map(delegation_map)) = map.get("delegation") {
        let Some(CborValue::ByteString(subnet_id)) = delegation_map.get("subnet_id") else {
            return Err(ResponseVerificationError::MalformedCertificate(
                "Expected Delegation Map to contain a Subnet ID when parsing Certificate Cbor".into()
            ));
        };

        let Some(CborValue::ByteString(certificate)) = delegation_map.get("certificate") else {
            return Err(ResponseVerificationError::MalformedCertificate(
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
    use crate::test_utils::test_utils::{create_certificate, create_certificate_delegation};

    #[test]
    fn deserialize_from_cbor() {
        let certificate = create_certificate(None);

        let cbor = serde_cbor::to_vec(&certificate).unwrap();

        let result = Certificate::from_cbor(&cbor).unwrap();

        assert_eq!(result, certificate);
    }

    #[test]
    fn deserialize_from_cbor_with_delegation() {
        let mut certificate = create_certificate(None);
        certificate.delegation = Some(create_certificate_delegation());

        let cbor = serde_cbor::to_vec(&certificate).unwrap();

        let result = Certificate::from_cbor(&cbor).unwrap();

        assert_eq!(result, certificate);
    }
}
