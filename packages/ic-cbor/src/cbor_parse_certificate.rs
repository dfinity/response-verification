use crate::{parse_cbor, parsed_cbor_to_tree, CborError, CborResult, CborValue};
use ic_certification::{Certificate, Delegation};

pub trait CertificateToCbor {
    fn from_cbor(cbor: &[u8]) -> CborResult<Certificate>;
}

impl CertificateToCbor for Certificate {
    fn from_cbor(cbor: &[u8]) -> CborResult<Certificate> {
        let parsed_cbor = parse_cbor(cbor).map_err(|e| CborError::MalformedCbor(e.to_string()))?;

        parsed_cbor_to_certificate(parsed_cbor)
    }
}

fn parsed_cbor_to_certificate(parsed_cbor: CborValue) -> CborResult<Certificate> {
    let CborValue::Map(map) = parsed_cbor else {
        return Err(CborError::MalformedCertificate(
            "Expected Map when parsing Certificate Cbor".into(),
        ));
    };

    let Some(tree_cbor) = map.get("tree") else {
        return Err(CborError::MalformedCertificate(
            "Expected Tree when parsing Certificate Cbor".into(),
        ));
    };

    let tree = parsed_cbor_to_tree(tree_cbor)?;

    let signature = if let Some(CborValue::ByteString(signature)) = map.get("signature") {
        signature.to_owned()
    } else {
        return Err(CborError::MalformedCertificate(
            "Expected Signature when parsing Certificate Cbor".into(),
        ));
    };

    let delegation = if let Some(CborValue::Map(delegation_map)) = map.get("delegation") {
        let Some(CborValue::ByteString(subnet_id)) = delegation_map.get("subnet_id") else {
            return Err(CborError::MalformedCertificate(
                "Expected Delegation Map to contain a Subnet ID when parsing Certificate Cbor"
                    .into(),
            ));
        };

        let Some(CborValue::ByteString(certificate)) = delegation_map.get("certificate") else {
            return Err(CborError::MalformedCertificate(
                "Expected Delegation Map to contain a Certificate when parsing Certificate Cbor"
                    .into(),
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
    use ic_response_verification_test_utils::{
        cbor_encode, create_certificate, create_certificate_delegation,
    };

    #[test]
    fn deserialize_from_cbor() {
        let certificate = create_certificate(None);

        let cbor = cbor_encode(&certificate);

        let result = Certificate::from_cbor(&cbor).unwrap();

        assert_eq!(result, certificate);
    }

    #[test]
    fn deserialize_from_cbor_with_delegation() {
        let mut certificate = create_certificate(None);
        certificate.delegation = Some(create_certificate_delegation());

        let cbor = cbor_encode(&certificate);

        let result = Certificate::from_cbor(&cbor).unwrap();

        assert_eq!(result, certificate);
    }
}
