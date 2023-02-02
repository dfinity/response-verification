use candid::Principal;
use ic_certification::{Certificate, Delegation, HashTree, LookupResult};
use miracl_core_bls12381::bls12381::bls::{core_verify, BLS_OK};

use crate::cbor::certificate::CertificateToCbor;
use crate::cbor::parse_cbor_principals_array;
use crate::error::{ResponseVerificationError, ResponseVerificationResult};

const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";
const DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";
const KEY_LENGTH: usize = 96;

pub fn extract_der(buf: Vec<u8>) -> ResponseVerificationResult<Vec<u8>> {
    let expected_length = DER_PREFIX.len() + KEY_LENGTH;
    if buf.len() != expected_length {
        return Err(ResponseVerificationError::DerKeyLengthMismatch {
            expected: expected_length,
            actual: buf.len(),
        });
    }

    let prefix = &buf[0..DER_PREFIX.len()];
    if prefix[..] != DER_PREFIX[..] {
        return Err(ResponseVerificationError::DerPrefixMismatch {
            expected: DER_PREFIX.to_vec(),
            actual: prefix.to_vec(),
        });
    }

    let key = &buf[DER_PREFIX.len()..];
    Ok(key.to_vec())
}

pub fn principal_is_within_ranges(
    principal: &Principal,
    ranges: &[(Principal, Principal)],
) -> bool {
    ranges
        .iter()
        .any(|r| principal >= &r.0 && principal <= &r.1)
}

pub trait VerifyCertificate<T> {
    fn verify(&self, canister_id: &[u8], root_public_key: &[u8]) -> ResponseVerificationResult<T>;
}

impl VerifyCertificate<()> for Certificate<'_> {
    fn verify(&self, canister_id: &[u8], root_public_key: &[u8]) -> ResponseVerificationResult<()> {
        let sig = self.signature.as_slice();

        let root_hash = self.tree.digest();
        let mut msg = vec![];
        msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
        msg.extend_from_slice(&root_hash);

        let der_key = match &self.delegation {
            Some(delegation) => delegation.verify(canister_id, root_public_key)?,
            _ => root_public_key.into(),
        };
        let key = extract_der(der_key)?;

        match core_verify(sig, &msg, &key) {
            BLS_OK => Ok(()),
            _ => Err(ResponseVerificationError::CertificateVerificationFailed),
        }
    }
}

impl VerifyCertificate<Vec<u8>> for Delegation {
    fn verify(
        &self,
        canister_id: &[u8],
        root_public_key: &[u8],
    ) -> ResponseVerificationResult<Vec<u8>> {
        let cert: Certificate = Certificate::from_cbor(&self.certificate)?;
        cert.verify(canister_id, root_public_key)?;

        let LookupResult::Found(canister_range) = cert.tree.lookup_path(&[
            "subnet".into(),
            self.subnet_id.clone().into(),
            "canister_ranges".into(),
        ]) else {
            return Err(ResponseVerificationError::CertificateSubnetCanisterRangesNotFound);
        };

        let ranges: Vec<(Principal, Principal)> = parse_cbor_principals_array(canister_range)?;
        if !principal_is_within_ranges(&Principal::from_slice(canister_id), &ranges[..]) {
            // the certificate is not authorized to answer calls for this canister
            return Err(ResponseVerificationError::CertificatePrincipalOutOfRange);
        }

        let LookupResult::Found(subnet_public_key) = cert.tree.lookup_path(&[
            "subnet".into(),
            self.subnet_id.clone().into(),
            "public_key".into(),
        ]) else {
            return Err(ResponseVerificationError::CertificateSubnetPublicKeyNotFound);
        };

        Ok(subnet_public_key.into())
    }
}

pub fn validate_certificate_time(
    certificate: &Certificate,
    current_time_ns: &u128,
    allowed_certificate_time_offset: &u128,
) -> ResponseVerificationResult {
    let time_path = ["time".into()];

    let LookupResult::Found(mut encoded_certificate_time) = certificate.tree.lookup_path(&time_path) else {
        return Err(ResponseVerificationError::MissingTimePathInTree);
    };

    let certificate_time = leb128::read::unsigned(&mut encoded_certificate_time)
        .map_err(|_| ResponseVerificationError::LebDecodingOverflow)?
        as u128;
    let max_certificate_time = current_time_ns + allowed_certificate_time_offset;
    let min_certificate_time = current_time_ns - allowed_certificate_time_offset;

    if certificate_time > max_certificate_time {
        return Err(
            ResponseVerificationError::CertificateTimeTooFarInTheFuture {
                certificate_time,
                max_certificate_time,
            },
        );
    }

    if certificate_time < min_certificate_time {
        return Err(ResponseVerificationError::CertificateTimeTooFarInThePast {
            certificate_time,
            min_certificate_time,
        });
    }

    Ok(())
}

pub fn validate_tree(canister_id: &[u8], certificate: &Certificate, tree: &HashTree) -> bool {
    let certified_data_path = [
        "canister".into(),
        canister_id.into(),
        "certified_data".into(),
    ];

    let witness = match certificate.tree.lookup_path(&certified_data_path) {
        LookupResult::Found(witness) => witness,
        _ => {
            return false;
        }
    };

    let digest = tree.digest();
    if witness != digest {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::hash_tree::HashTreeToCbor;
    use ic_certification::hash_tree::HashTree;
    use ic_crypto_tree_hash::{flatmap, Label, LabeledTree};
    use ic_response_verification_test_utils::{
        create_canister_id, create_certified_data, get_current_timestamp, get_timestamp, AssetTree,
        CanisterData, CertificateBuilder, CertificateData,
    };
    use std::ops::{Add, Sub};
    use std::time::{Duration, SystemTime};

    static CANISTER_ID: &str = "r7inp-6aaaa-aaaaa-aaabq-cai";
    static OTHER_CANISTER_ID: &str = "rdmx6-jaaaa-aaaaa-aaadq-cai";
    const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000; // 5 min

    #[test]
    fn verify_certificate() {
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");
        let (_, root_key, cbor_encoded_certificate) = CertificateBuilder::new(
            CertificateData::CanisterData(CanisterData::default().with_canister_id(canister_id)),
        )
        .build();

        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();

        certificate.verify(canister_id.as_ref(), &root_key).unwrap();
    }

    #[test]
    fn verify_certificate_should_fail() {
        let wrong_ic_key: &[u8] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x08\x1a\x0b\xaa\xae";
        let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");
        let (_, _, cbor_encoded_certificate) = CertificateBuilder::new(
            CertificateData::CanisterData(CanisterData::default().with_canister_id(canister_id)),
        )
        .build();

        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();

        let result = certificate.verify(canister_id.as_ref(), wrong_ic_key);

        assert!(matches!(
            result.err(),
            Some(ResponseVerificationError::CertificateVerificationFailed),
        ))
    }

    #[test]
    fn validate_certificate_time_with_suitable_time() {
        let current_timestamp = get_current_timestamp();

        let (_, _, cbor_encoded_certificate) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData::default()))
                .with_time(current_timestamp)
                .build();
        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();

        validate_certificate_time(&certificate, &current_timestamp, &MAX_CERT_TIME_OFFSET_NS)
            .unwrap();
    }

    #[test]
    fn validate_certificate_time_with_time_too_far_in_the_future() {
        let current_timestamp = get_current_timestamp();

        let future_time = SystemTime::now().add(Duration::new(301, 0));
        let future_timestamp = get_timestamp(future_time);

        let (_, _, cbor_encoded_certificate) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData::default()))
                .with_time(future_timestamp)
                .build();
        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();

        assert!(matches!(
            validate_certificate_time(&certificate, &current_timestamp, &MAX_CERT_TIME_OFFSET_NS).err(),
            Some(ResponseVerificationError::CertificateTimeTooFarInTheFuture { certificate_time, max_certificate_time })
                if certificate_time == future_timestamp && max_certificate_time == current_timestamp + MAX_CERT_TIME_OFFSET_NS
        ))
    }

    #[test]
    fn validate_certificate_time_with_time_too_far_in_the_past() {
        let current_timestamp = get_current_timestamp();

        let past_time = SystemTime::now().sub(Duration::new(301, 0));
        let past_timestamp = get_timestamp(past_time);

        let (_, _, cbor_encoded_certificate) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData::default()))
                .with_time(past_timestamp)
                .build();
        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();

        assert!(matches!(
            validate_certificate_time(&certificate, &current_timestamp, &MAX_CERT_TIME_OFFSET_NS).err(),
            Some(ResponseVerificationError::CertificateTimeTooFarInThePast { certificate_time, min_certificate_time })
                if certificate_time == past_timestamp && min_certificate_time == current_timestamp - MAX_CERT_TIME_OFFSET_NS
        ))
    }

    #[test]
    fn validate_tree_with_matching_digest() {
        let canister_id = create_canister_id(CANISTER_ID);
        let tree = AssetTree::default();
        let certified_data = tree.get_certified_data();

        let (_, _, cbor_encoded_certificate) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id,
                certified_data,
            }))
            .build();
        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();
        let tree = HashTree::from_cbor(&tree.serialize_to_cbor(None)).unwrap();

        let result = validate_tree(canister_id.as_ref(), &certificate, &tree);

        assert!(result);
    }

    #[test]
    fn validate_tree_with_mismatching_digest() {
        let canister_id = create_canister_id(CANISTER_ID);
        let tree = AssetTree::default();
        let certified_data = create_certified_data(
            "8160c07b45d617dba08a20eaa71ace28b5962965034b7539e42ebdb80da729a9",
        );

        let (_, _, cbor_encoded_certificate) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id,
                certified_data,
            }))
            .build();
        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();
        let tree = HashTree::from_cbor(&tree.serialize_to_cbor(None)).unwrap();

        let result = validate_tree(canister_id.as_ref(), &certificate, &tree);

        assert!(!result);
    }

    #[test]
    fn validate_tree_with_incorrect_canister_id() {
        let canister_id = create_canister_id(CANISTER_ID);
        let other_canister_id = create_canister_id(OTHER_CANISTER_ID);
        let tree = AssetTree::default();
        let certified_data = tree.get_certified_data();

        let (_, _, cbor_encoded_certificate) =
            CertificateBuilder::new(CertificateData::CanisterData(CanisterData {
                canister_id: other_canister_id,
                certified_data,
            }))
            .build();
        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();
        let tree = HashTree::from_cbor(&tree.serialize_to_cbor(None)).unwrap();

        let result = validate_tree(canister_id.as_ref(), &certificate, &tree);

        assert!(!result);
    }

    #[test]
    fn validate_tree_without_certified_data() {
        let canister_id = create_canister_id(CANISTER_ID);
        let tree = AssetTree::default();
        let certified_data = create_certified_data(
            "8160c07b45d617dba08a20eaa71ace28b5962965034b7539e42ebdb80da729a9",
        );

        let certificate_tree = LabeledTree::SubTree(flatmap![
            Label::from("canister") => LabeledTree::SubTree(flatmap![
                Label::from(canister_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("garbage_data") => LabeledTree::Leaf(certified_data.to_vec()),
                ])
            ]),
        ]);
        let (_, _, cbor_encoded_certificate) =
            CertificateBuilder::new(CertificateData::CustomTree(certificate_tree)).build();
        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();
        let tree = HashTree::from_cbor(&tree.serialize_to_cbor(None)).unwrap();

        let result = validate_tree(canister_id.as_ref(), &certificate, &tree);

        assert!(!result);
    }
}
