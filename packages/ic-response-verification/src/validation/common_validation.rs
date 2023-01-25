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

        match core_verify(&sig, &msg, &key) {
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
        let cert: Certificate = Certificate::from_cbor(self.certificate.clone())?;
        cert.verify(canister_id, root_public_key)?;

        let LookupResult::Found(canister_range) = cert.tree.lookup_path(&[
            "subnet".into(),
            self.subnet_id.clone().into(),
            "canister_ranges".into(),
        ]) else {
            return Err(ResponseVerificationError::CertificateSubnetCanisterRangesNotFound);
        };

        let ranges: Vec<(Principal, Principal)> = parse_cbor_principals_array(&canister_range)?;
        if !principal_is_within_ranges(&Principal::from_slice(canister_id), &ranges[..]) {
            // the certificate is not authorized to answer calls for this canister
            return Err(ResponseVerificationError::CertificatePrincipalOutOfRange);
        }

        let LookupResult::Found(subnet_public_key) = cert.tree.lookup_path(&[
            "subnet".into(),
            self.subnet_id.clone().into(),
            "public_key".into(),
        ]) else {
            return Err(ResponseVerificationError::CertificateSubnetPublicKeyNotFound)
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

    let LookupResult::Found(encoded_certificate_time) = certificate.tree.lookup_path(&time_path) else {
        return Err(ResponseVerificationError::MissingTimePathInTree);
    };

    let certificate_time = leb128::read::unsigned(&mut encoded_certificate_time.as_ref())
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

    return true;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate_header::CertificateHeader;
    use crate::test_utils::test_utils::{
        create_certificate, create_tree, CreateCertificateOptions,
    };
    use candid::Principal;
    use ic_certification::hash_tree::{label, leaf};
    use std::ops::{Add, Sub};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static IC_ROOT_KEY: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x09\x1a\x0b\xaa\xae";
    static CANISTER_ID: &str = "r7inp-6aaaa-aaaaa-aaabq-cai";
    static OTHER_CANISTER_ID: &str = "rdmx6-jaaaa-aaaaa-aaadq-cai";
    const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000; // 5 min

    fn get_timestamp(time: SystemTime) -> u128 {
        time.duration_since(UNIX_EPOCH).unwrap().as_nanos()
    }

    fn leb_encode_timestamp(timestamp: u128) -> [u8; 1024] {
        let mut buf = [0; 1024];
        let mut writable = &mut buf[..];
        leb128::write::unsigned(&mut writable, timestamp as u64).unwrap();

        buf
    }

    #[test]
    fn verify_certificate() {
        let certificate_header = CertificateHeader::from("certificate=:2dn3o2R0cmVlgwGDAYMBgwJIY2FuaXN0ZXKDAkoAAAAAAAAABwEBgwGDAYMBgwJOY2VydGlmaWVkX2RhdGGCA1gg2e9+GWTYWw6giMkxjJE7dxUuFMOmoEJ30FFRTOYmZ+6CBFgg/VtZRZdYyK/sr3KF2jWeS1rblF+4ajwfDv2ZbCGpaTiCBFgg6HKEMFmYn9j0sFHRxCCDNXWTLnDMbw4tDvk9Rh2gPymCBFggKBqd8UfSTdcsbnzQLZPXVYsJLM6dc/fi+RlcW9D/WJGCBFgggAG4QoPuBpdUD9ifMs40Cvn9vn0wahLjSTMOBsMV4iCCBFggoawiEDD+DnBTi5j9NjLHMWHFAlWaVk4+26+ulwFUYJ6DAYIEWCALLxLPg6ijOWkcDTm+OEMs7hpk2o44mLtpr9tpcII8XoMCRHRpbWWCA0mvsY3usNqMlRdpc2lnbmF0dXJlWDCGny0r7KOVEzQsoU4URu/jteB+cO4uw8x59WgP3akcM4hQZ2FLVtbWwKgX2OXKBBVqZGVsZWdhdGlvbqJpc3VibmV0X2lkWB1D3K8RgNuC/acIzjrHoDpgYKveE+lUbGDozOZdAmtjZXJ0aWZpY2F0ZVkCbtnZ96JkdHJlZYMBggRYIOdSJxF174WaX2n7+PrVTskgyInEKI4+qd19HkTmpD4ugwGDAkZzdWJuZXSDAYMBgwGCBFggJn/lURG1bjw5dVMuozc/e3Lp+CBy/o5gftNEhkeKWzmDAYIEWCBGanAobPms6YAcpT4ir27gWaCU/WBJhgbUhLaFQFgwfYMBgwGCBFggiy9sFQeK5NO5NHCRXKU+NzMn836nS6G4F32Ya7ebMa6DAlgdQ9yvEYDbgv2nCM46x6A6YGCr3hPpVGxg6MzmXQKDAYMCT2NhbmlzdGVyX3Jhbmdlc4IDWDLZ2feCgkoAAAAAAAAABwEBSgAAAAAAAAAHAQGCSgAAAAACEAAAAQFKAAAAAAIf//8BAYMCSnB1YmxpY19rZXmCA1iFMIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIZ1tjSkPjlyYjjP45yVGLw+MiXLb1qEeb/PK2CPum+FJNy4DzWorkS0fyYvCmYg1BJ58G/gxTpzn8ygGkiSb+ZRo1GbWzKf++zJ8MuQiwmN0+iEXPuZxWN54EmsRl7IBoIEWCCHzSE2R03mBIh5w7cCAFNWUXA9yXLKy5T6Bl/+LuY2ioIEWCBKHXbAjmQuPbaYLmZTvoxzbydaJKwiEINDCy1bRBznVIIEWCAthWu6e2yAFxzo5dEhu35EULNWWmRNkTXp/liEKBwfuYMCRHRpbWWCA0m10ovcy4SWlBdpc2lnbmF0dXJlWDCt6yOQsJ6yXcx8WbPabC32P4fss5zCAYh1/Jal1encJWqqxbAD9Svz7bsCIYWs1Ec=:, tree=:2dn3gwGDAktodHRwX2Fzc2V0c4MBgwGDAkEvggNYIHhMD4Jak4qn9HFYfN98d5b4KPk2JJXiuchJDyIyNZvbggRYINfNCmz1KiBw3FH+HXtqhweIiHGeFoScdIw15/x7aflcggRYIFgrUyEzZkbUjG+L8ZEzM7tOv2XAn/v4IHwBLh9UBxJhggRYICEzSyZoHXIg49LX3LI6iczbGx4ETrNeu+SR9m1AgNB4:");
        let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
        let certificate = certificate_header
            .certificate
            .and_then(|certificate| Some(Certificate::from_cbor(certificate)))
            .transpose()
            .unwrap()
            .unwrap();

        certificate
            .verify(canister_id.as_slice(), IC_ROOT_KEY)
            .unwrap();
    }

    #[test]
    fn verify_certificate_should_fail() {
        let wrong_ic_key: &[u8; 133] = b"\x30\x81\x82\x30\x1d\x06\x0d\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x01\x02\x01\x06\x0c\x2b\x06\x01\x04\x01\x82\xdc\x7c\x05\x03\x02\x01\x03\x61\x00\x81\x4c\x0e\x6e\xc7\x1f\xab\x58\x3b\x08\xbd\x81\x37\x3c\x25\x5c\x3c\x37\x1b\x2e\x84\x86\x3c\x98\xa4\xf1\xe0\x8b\x74\x23\x5d\x14\xfb\x5d\x9c\x0c\xd5\x46\xd9\x68\x5f\x91\x3a\x0c\x0b\x2c\xc5\x34\x15\x83\xbf\x4b\x43\x92\xe4\x67\xdb\x96\xd6\x5b\x9b\xb4\xcb\x71\x71\x12\xf8\x47\x2e\x0d\x5a\x4d\x14\x50\x5f\xfd\x74\x84\xb0\x12\x91\x09\x1c\x5f\x87\xb9\x88\x83\x46\x3f\x98\x08\x1a\x0b\xaa\xae";
        let certificate_header = CertificateHeader::from("certificate=:2dn3o2R0cmVlgwGDAYMBgwJIY2FuaXN0ZXKDAkoAAAAAAAAABwEBgwGDAYMBgwJOY2VydGlmaWVkX2RhdGGCA1gg2e9+GWTYWw6giMkxjJE7dxUuFMOmoEJ30FFRTOYmZ+6CBFgg/VtZRZdYyK/sr3KF2jWeS1rblF+4ajwfDv2ZbCGpaTiCBFgg6HKEMFmYn9j0sFHRxCCDNXWTLnDMbw4tDvk9Rh2gPymCBFggKBqd8UfSTdcsbnzQLZPXVYsJLM6dc/fi+RlcW9D/WJGCBFgggAG4QoPuBpdUD9ifMs40Cvn9vn0wahLjSTMOBsMV4iCCBFggoawiEDD+DnBTi5j9NjLHMWHFAlWaVk4+26+ulwFUYJ6DAYIEWCALLxLPg6ijOWkcDTm+OEMs7hpk2o44mLtpr9tpcII8XoMCRHRpbWWCA0mvsY3usNqMlRdpc2lnbmF0dXJlWDCGny0r7KOVEzQsoU4URu/jteB+cO4uw8x59WgP3akcM4hQZ2FLVtbWwKgX2OXKBBVqZGVsZWdhdGlvbqJpc3VibmV0X2lkWB1D3K8RgNuC/acIzjrHoDpgYKveE+lUbGDozOZdAmtjZXJ0aWZpY2F0ZVkCbtnZ96JkdHJlZYMBggRYIOdSJxF174WaX2n7+PrVTskgyInEKI4+qd19HkTmpD4ugwGDAkZzdWJuZXSDAYMBgwGCBFggJn/lURG1bjw5dVMuozc/e3Lp+CBy/o5gftNEhkeKWzmDAYIEWCBGanAobPms6YAcpT4ir27gWaCU/WBJhgbUhLaFQFgwfYMBgwGCBFggiy9sFQeK5NO5NHCRXKU+NzMn836nS6G4F32Ya7ebMa6DAlgdQ9yvEYDbgv2nCM46x6A6YGCr3hPpVGxg6MzmXQKDAYMCT2NhbmlzdGVyX3Jhbmdlc4IDWDLZ2feCgkoAAAAAAAAABwEBSgAAAAAAAAAHAQGCSgAAAAACEAAAAQFKAAAAAAIf//8BAYMCSnB1YmxpY19rZXmCA1iFMIGCMB0GDSsGAQQBgtx8BQMBAgEGDCsGAQQBgtx8BQMCAQNhAIZ1tjSkPjlyYjjP45yVGLw+MiXLb1qEeb/PK2CPum+FJNy4DzWorkS0fyYvCmYg1BJ58G/gxTpzn8ygGkiSb+ZRo1GbWzKf++zJ8MuQiwmN0+iEXPuZxWN54EmsRl7IBoIEWCCHzSE2R03mBIh5w7cCAFNWUXA9yXLKy5T6Bl/+LuY2ioIEWCBKHXbAjmQuPbaYLmZTvoxzbydaJKwiEINDCy1bRBznVIIEWCAthWu6e2yAFxzo5dEhu35EULNWWmRNkTXp/liEKBwfuYMCRHRpbWWCA0m10ovcy4SWlBdpc2lnbmF0dXJlWDCt6yOQsJ6yXcx8WbPabC32P4fss5zCAYh1/Jal1encJWqqxbAD9Svz7bsCIYWs1Ec=:, tree=:2dn3gwGDAktodHRwX2Fzc2V0c4MBgwGDAkEvggNYIHhMD4Jak4qn9HFYfN98d5b4KPk2JJXiuchJDyIyNZvbggRYINfNCmz1KiBw3FH+HXtqhweIiHGeFoScdIw15/x7aflcggRYIFgrUyEzZkbUjG+L8ZEzM7tOv2XAn/v4IHwBLh9UBxJhggRYICEzSyZoHXIg49LX3LI6iczbGx4ETrNeu+SR9m1AgNB4:");
        let canister_id = Principal::from_text("rdmx6-jaaaa-aaaaa-aaadq-cai").unwrap();
        let certificate = certificate_header
            .certificate
            .and_then(|certificate| Some(Certificate::from_cbor(certificate)))
            .transpose()
            .unwrap()
            .unwrap();

        let verification = certificate.verify(canister_id.as_slice(), wrong_ic_key);

        assert!(matches!(
            verification.err(),
            Some(ResponseVerificationError::CertificateVerificationFailed),
        ))
    }

    #[test]
    fn validate_certificate_time_with_suitable_time() {
        let current_time = SystemTime::now();
        let current_timestamp = get_timestamp(current_time);
        let encoded_timestamp = leb_encode_timestamp(current_timestamp);

        let certificate_options = CreateCertificateOptions {
            time: Some(&encoded_timestamp),
            canister_id: None,
            certified_data: None,
        };
        let certificate = create_certificate(Some(certificate_options));

        validate_certificate_time(&certificate, &current_timestamp, &MAX_CERT_TIME_OFFSET_NS)
            .unwrap();
    }

    #[test]
    fn validate_certificate_time_with_time_too_far_in_the_future() {
        let current_time = SystemTime::now();
        let current_timestamp = get_timestamp(current_time);

        let future_time = current_time.add(Duration::new(301, 0));
        let future_timestamp = get_timestamp(future_time);
        let encoded_future_timestamp = leb_encode_timestamp(future_timestamp);

        let certificate_options = CreateCertificateOptions {
            time: Some(&encoded_future_timestamp),
            canister_id: None,
            certified_data: None,
        };
        let certificate = create_certificate(Some(certificate_options));

        assert!(matches!(
            validate_certificate_time(&certificate, &current_timestamp, &MAX_CERT_TIME_OFFSET_NS).err(),
            Some(ResponseVerificationError::CertificateTimeTooFarInTheFuture { certificate_time, max_certificate_time })
                if certificate_time == future_timestamp && max_certificate_time == current_timestamp + MAX_CERT_TIME_OFFSET_NS
        ))
    }

    #[test]
    fn validate_certificate_time_with_time_too_far_in_the_past() {
        let current_time = SystemTime::now();
        let current_timestamp = get_timestamp(current_time);

        let past_time = current_time.sub(Duration::new(301, 0));
        let past_timestamp = get_timestamp(past_time);
        let encoded_past_timestamp = leb_encode_timestamp(past_timestamp);

        let certificate_options = CreateCertificateOptions {
            time: Some(&encoded_past_timestamp),
            canister_id: None,
            certified_data: None,
        };
        let certificate = create_certificate(Some(certificate_options));

        assert!(matches!(
            validate_certificate_time(&certificate, &current_timestamp, &MAX_CERT_TIME_OFFSET_NS).err(),
            Some(ResponseVerificationError::CertificateTimeTooFarInThePast { certificate_time, min_certificate_time })
                if certificate_time == past_timestamp && min_certificate_time == current_timestamp - MAX_CERT_TIME_OFFSET_NS
        ))
    }

    #[test]
    fn validate_tree_with_matching_digest() {
        let principal = Principal::from_text(CANISTER_ID).unwrap();
        let tree = create_tree(None);
        let digest = tree.digest();

        let certificate_options = CreateCertificateOptions {
            time: None,
            canister_id: Some(principal.as_slice()),
            certified_data: Some(&digest),
        };
        let certificate = create_certificate(Some(certificate_options));

        let result = validate_tree(principal.as_slice(), &certificate, &tree);

        assert_eq!(result, true);
    }

    #[test]
    fn validate_tree_with_mismatching_digest() {
        let principal = Principal::from_text(CANISTER_ID).unwrap();
        let tree = create_tree(None);

        let certificate_options = CreateCertificateOptions {
            time: None,
            canister_id: Some(principal.as_slice()),
            certified_data: Some(&[1, 2, 3, 4, 5, 6]),
        };
        let certificate = create_certificate(Some(certificate_options));

        let result = validate_tree(principal.as_slice(), &certificate, &tree);

        assert_eq!(result, false);
    }

    #[test]
    fn validate_tree_with_incorrect_canister_id() {
        let principal = Principal::from_text(CANISTER_ID).unwrap();
        let other_principal = Principal::from_text(OTHER_CANISTER_ID).unwrap();
        let tree = create_tree(None);
        let digest = tree.digest();

        let certificate_options = CreateCertificateOptions {
            time: None,
            canister_id: Some(other_principal.as_slice()),
            certified_data: Some(&digest),
        };
        let certificate = create_certificate(Some(certificate_options));

        let result = validate_tree(principal.as_slice(), &certificate, &tree);

        assert_eq!(result, false);
    }

    #[test]
    fn validate_tree_without_certified_data() {
        let principal = Principal::from_text(CANISTER_ID).unwrap();
        let tree = create_tree(None);
        let certificate_tree = label(
            "canister",
            label(
                principal.as_slice(),
                label("garbage_data", leaf([1, 2, 3, 4, 5, 6])),
            ),
        );
        let certificate = Certificate {
            tree: certificate_tree,
            signature: vec![],
            delegation: None,
        };

        let result = validate_tree(principal.as_slice(), &certificate, &tree);

        assert_eq!(result, false);
    }
}
