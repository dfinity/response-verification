use crate::{
    error::{CertificateVerificationError, CertificateVerificationResult},
    signature_verification::verify_signature,
};
use candid::Principal;
use ic_cbor::{parse_cbor_principals_array, CertificateToCbor};
use ic_certification::{Certificate, Delegation, LookupResult};

const IC_STATE_ROOT_DOMAIN_SEPARATOR: &[u8; 14] = b"\x0Dic-state-root";
const DER_PREFIX: &[u8; 37] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00";
const KEY_LENGTH: usize = 96;

fn extract_der(buf: &[u8]) -> CertificateVerificationResult<Vec<u8>> {
    let expected_length = DER_PREFIX.len() + KEY_LENGTH;
    if buf.len() != expected_length {
        return Err(CertificateVerificationError::DerKeyLengthMismatch {
            expected: expected_length,
            actual: buf.len(),
        });
    }

    let prefix = &buf[0..DER_PREFIX.len()];
    if prefix[..] != DER_PREFIX[..] {
        return Err(CertificateVerificationError::DerPrefixMismatch {
            expected: DER_PREFIX.to_vec(),
            actual: prefix.to_vec(),
        });
    }

    let key = &buf[DER_PREFIX.len()..];
    Ok(key.to_vec())
}

fn principal_is_within_ranges(principal: &Principal, ranges: &[(Principal, Principal)]) -> bool {
    ranges
        .iter()
        .any(|r| principal >= &r.0 && principal <= &r.1)
}

pub trait VerifyCertificate<T> {
    fn verify(
        &self,
        canister_id: &[u8],
        root_public_key: &[u8],
        current_time_ns: &u128,
        allowed_certificate_time_offset: &u128,
    ) -> CertificateVerificationResult<T>;
}

impl VerifyCertificate<()> for Certificate {
    fn verify(
        &self,
        canister_id: &[u8],
        root_public_key: &[u8],
        current_time_ns: &u128,
        allowed_certificate_time_offset: &u128,
    ) -> CertificateVerificationResult<()> {
        verify_certificate_time(self, current_time_ns, allowed_certificate_time_offset)?;

        let der_key = match &self.delegation {
            Some(delegation) => verify_delegation(delegation, canister_id, root_public_key)?,
            _ => root_public_key.into(),
        };
        verify_certificate_signature(self, &der_key)
    }
}

fn verify_delegation(
    delegation: &Delegation,
    canister_id: &[u8],
    root_public_key: &[u8],
) -> CertificateVerificationResult<Vec<u8>> {
    let cert: Certificate = Certificate::from_cbor(&delegation.certificate)?;

    // disallow nested delegations
    if cert.delegation.is_some() {
        return Err(CertificateVerificationError::CertificateHasTooManyDelegations);
    }

    // verify the certificate's signature only
    // the certificate's time is not verified here because the delegation
    // is not reissued to the subnet on a regular basis
    verify_certificate_signature(&cert, root_public_key)?;

    let canister_range_path = [
        "subnet".as_bytes(),
        delegation.subnet_id.as_ref(),
        "canister_ranges".as_bytes(),
    ];
    let LookupResult::Found(canister_range) = cert.tree.lookup_path(&canister_range_path) else {
        return Err(
            CertificateVerificationError::SubnetCanisterIdRangesNotFound {
                path: canister_range_path.iter().map(|p| p.to_vec()).collect(),
            },
        );
    };

    let canister_id = Principal::from_slice(canister_id);
    let canister_ranges: Vec<(Principal, Principal)> = parse_cbor_principals_array(canister_range)?;
    if !principal_is_within_ranges(&canister_id, &canister_ranges[..]) {
        // the certificate is not authorized to answer calls for this canister
        return Err(CertificateVerificationError::PrincipalOutOfRange {
            canister_id,
            canister_ranges,
        });
    }

    let public_key_path = [
        "subnet".as_bytes(),
        delegation.subnet_id.as_ref(),
        "public_key".as_bytes(),
    ];
    let LookupResult::Found(subnet_public_key) = cert.tree.lookup_path(&public_key_path) else {
        return Err(CertificateVerificationError::SubnetPublicKeyNotFound {
            path: public_key_path.iter().map(|p| p.to_vec()).collect(),
        });
    };

    Ok(subnet_public_key.into())
}

fn verify_certificate_time(
    certificate: &Certificate,
    current_time_ns: &u128,
    allowed_certificate_time_offset: &u128,
) -> CertificateVerificationResult {
    let time_path = ["time".as_bytes()];

    let LookupResult::Found(mut encoded_certificate_time) =
        certificate.tree.lookup_path(&time_path)
    else {
        return Err(CertificateVerificationError::MissingTimePathInTree {
            path: time_path.iter().map(|p| p.to_vec()).collect(),
        });
    };

    let certificate_time = leb128::read::unsigned(&mut encoded_certificate_time).map_err(|_| {
        CertificateVerificationError::TimeDecodingFailed {
            timestamp: encoded_certificate_time.to_vec(),
        }
    })? as u128;
    let max_certificate_time = current_time_ns + allowed_certificate_time_offset;
    let min_certificate_time = current_time_ns - allowed_certificate_time_offset;

    if certificate_time > max_certificate_time {
        return Err(CertificateVerificationError::TimeTooFarInTheFuture {
            certificate_time,
            max_certificate_time,
        });
    }

    if certificate_time < min_certificate_time {
        return Err(CertificateVerificationError::TimeTooFarInThePast {
            certificate_time,
            min_certificate_time,
        });
    }

    Ok(())
}

fn verify_certificate_signature(
    certificate: &Certificate,
    der_key: &[u8],
) -> CertificateVerificationResult {
    let sig = certificate.signature.as_slice();

    let root_hash = certificate.tree.digest();
    let mut msg = vec![];
    msg.extend_from_slice(IC_STATE_ROOT_DOMAIN_SEPARATOR);
    msg.extend_from_slice(&root_hash);

    let pk = extract_der(der_key)?;

    verify_signature(&pk, sig, &msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_cbor::CertificateToCbor;
    use ic_certification::Certificate;
    use ic_certification_testing::{CertificateBuilder, CertificateData};
    use ic_response_verification_test_utils::{get_current_timestamp, get_timestamp, AssetTree};
    use ic_types::CanisterId;
    use std::{
        ops::{Add, Sub},
        time::{Duration, SystemTime},
    };

    const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000; // 5 min

    #[test]
    fn verify_certificate() {
        let canister_id = CanisterId::from_u64(0);
        let current_timestamp = get_current_timestamp();
        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(
            &canister_id.to_string(),
            &AssetTree::new().get_certified_data(),
        )
        .unwrap()
        .with_time(current_timestamp)
        .build()
        .unwrap();

        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();

        certificate
            .verify(
                canister_id.as_ref(),
                &root_key,
                &current_timestamp,
                &MAX_CERT_TIME_OFFSET_NS,
            )
            .unwrap();
    }

    #[test]
    fn verify_certificate_with_delegation() {
        let canister_id = CanisterId::from_u64(0);
        let current_timestamp = get_current_timestamp();
        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(
            &canister_id.to_string(),
            &AssetTree::new().get_certified_data(),
        )
        .unwrap()
        .with_time(current_timestamp)
        .with_delegation(123, vec![(0, 9)])
        .build()
        .unwrap();

        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();

        certificate
            .verify(
                canister_id.as_ref(),
                &root_key,
                &current_timestamp,
                &MAX_CERT_TIME_OFFSET_NS,
            )
            .unwrap();
    }

    #[test]
    fn verify_certificate_with_nested_delegation() {
        let canister_id = CanisterId::from_u64(0);
        let current_timestamp = get_current_timestamp();
        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(
            &canister_id.to_string(),
            &AssetTree::new().get_certified_data(),
        )
        .unwrap()
        .with_time(current_timestamp)
        .with_delegation(123, vec![(0, 9)])
        .with_nested_delegation(456, vec![(20, 19)])
        .build()
        .unwrap();

        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();

        let result = certificate
            .verify(
                canister_id.as_ref(),
                &root_key,
                &current_timestamp,
                &MAX_CERT_TIME_OFFSET_NS,
            )
            .unwrap_err();

        assert!(matches!(
            result,
            CertificateVerificationError::CertificateHasTooManyDelegations,
        ))
    }

    #[test]
    fn verify_certificate_with_incorrect_canister_range() {
        let wrong_canister_id = CanisterId::from_u64(10);
        let current_timestamp = get_current_timestamp();
        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(
            &wrong_canister_id.to_string(),
            &AssetTree::new().get_certified_data(),
        )
        .unwrap()
        .with_time(current_timestamp)
        .with_delegation(123, vec![(0, 9)])
        .build()
        .unwrap();

        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();

        let result = certificate
            .verify(
                wrong_canister_id.get().as_slice(),
                &root_key,
                &current_timestamp,
                &MAX_CERT_TIME_OFFSET_NS,
            )
            .unwrap_err();

        assert!(matches!(
            result,
            CertificateVerificationError::PrincipalOutOfRange {
                canister_id: _,
                canister_ranges: _
            }
        ))
    }

    #[test]
    fn verify_certificate_with_wrong_root_key() {
        let canister_id = CanisterId::from_u64(0);
        let current_timestamp = get_current_timestamp();
        let wrong_ic_key: &[u8] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x08\x1a\x0b\xaa\xae";
        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key: _,
        } = CertificateBuilder::new(
            &canister_id.to_string(),
            &AssetTree::new().get_certified_data(),
        )
        .unwrap()
        .with_time(current_timestamp)
        .build()
        .unwrap();

        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();

        let result = certificate
            .verify(
                canister_id.as_ref(),
                wrong_ic_key,
                &current_timestamp,
                &MAX_CERT_TIME_OFFSET_NS,
            )
            .unwrap_err();

        assert!(matches!(
            result,
            CertificateVerificationError::SignatureVerificationFailed
        ),)
    }

    #[test]
    fn verify_certificate_with_time_too_far_in_the_future() {
        let canister_id = CanisterId::from_u64(0);
        let current_timestamp = get_current_timestamp();

        let future_time = SystemTime::now().add(Duration::new(301, 0));
        let future_timestamp = get_timestamp(future_time);

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(
            &canister_id.to_string(),
            &AssetTree::new().get_certified_data(),
        )
        .unwrap()
        .with_time(future_timestamp)
        .build()
        .unwrap();

        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();

        let result = certificate
            .verify(
                canister_id.as_ref(),
                &root_key,
                &current_timestamp,
                &MAX_CERT_TIME_OFFSET_NS,
            )
            .unwrap_err();

        assert!(matches!(
            result,
            CertificateVerificationError::TimeTooFarInTheFuture { certificate_time, max_certificate_time }
                if certificate_time == future_timestamp && max_certificate_time == current_timestamp + MAX_CERT_TIME_OFFSET_NS
        ))
    }

    #[test]
    fn verify_certificate_with_time_too_far_in_the_past() {
        let canister_id = CanisterId::from_u64(0);
        let current_timestamp = get_current_timestamp();

        let past_time = SystemTime::now().sub(Duration::new(301, 0));
        let past_timestamp = get_timestamp(past_time);

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key,
        } = CertificateBuilder::new(
            &canister_id.to_string(),
            &AssetTree::new().get_certified_data(),
        )
        .unwrap()
        .with_time(past_timestamp)
        .build()
        .unwrap();
        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();

        let result = certificate
            .verify(
                canister_id.as_ref(),
                &root_key,
                &current_timestamp,
                &MAX_CERT_TIME_OFFSET_NS,
            )
            .unwrap_err();
        assert!(matches!(
            result,
            CertificateVerificationError::TimeTooFarInThePast { certificate_time, min_certificate_time }
                if certificate_time == past_timestamp && min_certificate_time == current_timestamp - MAX_CERT_TIME_OFFSET_NS
        ))
    }
}
