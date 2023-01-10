use http::Uri;
use ic_certification::{hash_tree::Sha256Digest, Certificate, HashTree, LookupResult};

use crate::error::{ResponseVerificationError, ResponseVerificationResult};

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

pub fn validate_body(tree: &HashTree, request_uri: &Uri, body_sha: &Sha256Digest) -> bool {
    let asset_path = ["http_assets".into(), request_uri.path().into()];
    let index_fallback_path = ["http_assets".into(), "/index.html".into()];

    let tree_sha = match tree.lookup_path(&asset_path) {
        LookupResult::Found(v) => v,

        // This is a strange fallback, but it is necessary for SPA routing at the moment.
        // https://internetcomputer.org/docs/current/references/ic-interface-spec/#http-gateway-certification
        //
        // It may be possible to remove this with a combination of asset canister redirect rules and v2 response verification.
        _ => match tree.lookup_path(&index_fallback_path) {
            LookupResult::Found(v) => v,
            _ => {
                return false;
            }
        },
    };

    return body_sha == tree_sha;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::body::decode_body_to_sha256;
    use crate::test_utils::test_utils::{
        create_certificate, create_tree, CreateCertificateOptions, CreateTreeOptions,
    };
    use candid::Principal;
    use ic_certification::hash_tree::{label, leaf};
    use std::ops::{Add, Sub};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    #[test]
    fn validate_body_with_matching_sha() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = decode_body_to_sha256(body, None).unwrap();
        let uri = format!("https://ic0.dev/app.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .unwrap();
        let tree_options = CreateTreeOptions {
            path: Some(&uri.path()),
            body_sha: Some(&body_sha),
        };
        let tree = create_tree(Some(tree_options));

        let result = validate_body(&tree, &uri, &body_sha);

        assert_eq!(result, true);
    }

    /// This is a strange fallback, but it is necessary for SPA routing at the moment.
    /// https://internetcomputer.org/docs/current/references/ic-interface-spec/#http-gateway-certification
    ///
    /// It may be possible to remove this with a combination of asset canister redirect rules and v2 response verification.
    #[test]
    fn validate_body_with_index_fallback() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = decode_body_to_sha256(body, None).unwrap();
        let uri = format!("https://ic0.dev/garbage.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .unwrap();
        let tree_options = CreateTreeOptions {
            path: Some(&"/index.html"),
            body_sha: Some(&body_sha),
        };
        let tree = create_tree(Some(tree_options));

        let result = validate_body(&tree, &uri, &body_sha);

        assert_eq!(result, true);
    }

    #[test]
    fn validate_body_without_index_fallback() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = decode_body_to_sha256(body, None).unwrap();
        let uri = format!("https://ic0.dev/app.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .unwrap();
        let tree_options = CreateTreeOptions {
            path: Some(&"/index.html"),
            body_sha: Some(&[9, 8, 7, 6, 5, 4, 3, 2, 1]),
        };
        let tree = create_tree(Some(tree_options));

        let result = validate_body(&tree, &uri, &body_sha);

        assert_eq!(result, false);
    }

    #[test]
    fn validate_body_without_matching_sha() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = decode_body_to_sha256(body, None).unwrap();
        let uri = format!("https://ic0.dev/app.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .unwrap();
        let tree_options = CreateTreeOptions {
            path: Some(&uri.path()),
            body_sha: Some(&[9, 8, 7, 6, 5, 4, 3, 2, 1]),
        };
        let tree = create_tree(Some(tree_options));

        let result = validate_body(&tree, &uri, &body_sha);

        assert_eq!(result, false);
    }

    #[test]
    fn validate_body_without_any_matching_path() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = decode_body_to_sha256(body, None).unwrap();
        let uri = format!("https://ic0.dev/app.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .unwrap();
        let tree_options = CreateTreeOptions {
            path: Some(&"/garbage.js"),
            body_sha: Some(&body_sha),
        };
        let tree = create_tree(Some(tree_options));

        let result = validate_body(&tree, &uri, &body_sha);

        assert_eq!(result, false);
    }
}
