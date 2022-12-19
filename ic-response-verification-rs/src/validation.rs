use http::Uri;
use ic_certification::{hash_tree::Sha256Digest, Certificate, HashTree, LookupResult};

use crate::error::{ResponseVerificationError, ResponseVerificationResult};
use crate::time::get_current_timestamp;

const MAX_CERT_TIME_OFFSET_IN_NS: u128 = 300_000_000_000; // 5 min

pub fn validate_certificate_time(certificate: &Certificate) -> ResponseVerificationResult {
    let time_path = ["time".into()];

    let LookupResult::Found(encoded_certificate_time) = certificate.tree.lookup_path(&time_path) else {
        return Err(ResponseVerificationError::MissingTimePathInTree);
    };

    let certificate_time = leb128::read::unsigned(&mut encoded_certificate_time.as_ref())
        .map_err(|_| ResponseVerificationError::LebDecodingOverflow)?
        as u128;
    let current_time = get_current_timestamp();
    let max_certificate_time = current_time + MAX_CERT_TIME_OFFSET_IN_NS;
    let min_certificate_time = current_time - MAX_CERT_TIME_OFFSET_IN_NS;

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
    use candid::Principal;
    use ic_certification::hash_tree::{fork, label, leaf};
    use std::ops::{Add, Sub};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    static CANISTER_ID: &str = "r7inp-6aaaa-aaaaa-aaabq-cai";
    static OTHER_CANISTER_ID: &str = "rdmx6-jaaaa-aaaaa-aaadq-cai";

    fn get_timestamp(time: SystemTime) -> u64 {
        time.duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
    }

    fn leb_encode_timestamp(timestamp: u64) -> [u8; 1024] {
        let mut buf = [0; 1024];
        let mut writable = &mut buf[..];
        leb128::write::unsigned(&mut writable, timestamp as u64)
            .expect("Failed to leb encode timestamp");

        buf
    }

    #[test]
    fn validate_certificate_time_with_suitable_time() {
        let current_time = SystemTime::now();

        let timestamp = get_timestamp(current_time);
        let encoded_timestamp = leb_encode_timestamp(timestamp);

        let certificate_tree = label("time", leaf(encoded_timestamp));
        let certificate = Certificate {
            tree: certificate_tree,
            signature: vec![],
            delegation: None,
        };

        validate_certificate_time(&certificate)
            .expect("Certificate time within expected time period");
    }

    #[test]
    #[should_panic]
    fn validate_certificate_time_with_time_too_far_in_the_future() {
        let current_time = SystemTime::now();
        let future_time = current_time.add(Duration::new(301, 0));

        let timestamp = get_timestamp(future_time);
        let encoded_timestamp = leb_encode_timestamp(timestamp);

        let certificate_tree = label("time", leaf(encoded_timestamp));
        let certificate = Certificate {
            tree: certificate_tree,
            signature: vec![],
            delegation: None,
        };

        validate_certificate_time(&certificate).unwrap();
    }

    #[test]
    #[should_panic]
    fn validate_certificate_time_with_time_too_far_in_the_past() {
        let current_time = SystemTime::now();
        let future_time = current_time.sub(Duration::new(301, 0));

        let timestamp = get_timestamp(future_time);
        let encoded_timestamp = leb_encode_timestamp(timestamp);

        let certificate_tree = label("time", leaf(encoded_timestamp));
        let certificate = Certificate {
            tree: certificate_tree,
            signature: vec![],
            delegation: None,
        };

        validate_certificate_time(&certificate).unwrap();
    }

    #[test]
    fn validate_tree_with_matching_digest() {
        let principal = Principal::from_text(CANISTER_ID).expect("Failed to create Principal");
        let tree = fork(leaf("a"), fork(leaf("b"), leaf("c")));
        let digest = tree.digest();
        let certificate_tree = label(
            "canister",
            label(principal.as_slice(), label("certified_data", leaf(digest))),
        );
        let certificate = Certificate {
            tree: certificate_tree,
            signature: vec![],
            delegation: None,
        };

        let result = validate_tree(principal.as_slice(), &certificate, &tree);

        assert_eq!(result, true);
    }

    #[test]
    fn validate_tree_with_mismatching_digest() {
        let principal = Principal::from_text(CANISTER_ID).expect("Failed to create Principal");
        let tree = fork(leaf("a"), fork(leaf("b"), leaf("c")));
        let certificate_tree = label(
            "canister",
            label(
                principal.as_slice(),
                label("certified_data", leaf([1, 2, 3, 4, 5, 6])),
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
    fn validate_tree_with_incorrect_canister_id() {
        let principal = Principal::from_text(CANISTER_ID).expect("Failed to create Principal");
        let other_principal =
            Principal::from_text(OTHER_CANISTER_ID).expect("Failed to create Principal");
        let tree = fork(leaf("a"), fork(leaf("b"), leaf("c")));
        let digest = tree.digest();
        let certificate_tree = label(
            "canister",
            label(
                other_principal.as_slice(),
                label("certified_data", leaf(digest)),
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
    fn validate_tree_without_certified_data() {
        let principal = Principal::from_text(CANISTER_ID).expect("Failed to create Principal");
        let tree = fork(leaf("a"), fork(leaf("b"), leaf("c")));
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
        let body_sha = decode_body_to_sha256(body, None).expect("Failed to decode body to sha245");

        let uri = format!("https://ic0.dev/app.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .expect("Failed to parse URI");
        let tree = label("http_assets", label(uri.path(), leaf(body_sha)));

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
        let body_sha = decode_body_to_sha256(body, None).expect("Failed to decode body to sha245");

        let uri = format!("https://ic0.dev/garbage.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .expect("Failed to parse URI");
        let tree = label("http_assets", label("/index.html", leaf(body_sha)));

        let result = validate_body(&tree, &uri, &body_sha);

        assert_eq!(result, true);
    }

    #[test]
    fn validate_body_without_index_fallback() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = decode_body_to_sha256(body, None).expect("Failed to decode body to sha245");

        let uri = format!("https://ic0.dev/app.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .expect("Failed to parse URI");
        let tree = label(
            "http_assets",
            label("/index.html", leaf([9, 8, 7, 6, 5, 4, 3, 2, 1])),
        );

        let result = validate_body(&tree, &uri, &body_sha);

        assert_eq!(result, false);
    }

    #[test]
    fn validate_body_without_matching_sha() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = decode_body_to_sha256(body, None).expect("Failed to decode body to sha245");

        let uri = format!("https://ic0.dev/app.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .expect("Failed to parse URI");
        let tree = label(
            "http_assets",
            label(uri.path(), leaf([9, 8, 7, 6, 5, 4, 3, 2, 1])),
        );

        let result = validate_body(&tree, &uri, &body_sha);

        assert_eq!(result, false);
    }

    #[test]
    fn validate_body_without_any_matching_path() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = decode_body_to_sha256(body, None).expect("Failed to decode body to sha245");

        let uri = format!("https://ic0.dev/app.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .expect("Failed to parse URI");
        let tree = label("http_assets", label("/garbage.js", leaf(body_sha)));

        let result = validate_body(&tree, &uri, &body_sha);

        assert_eq!(result, false);
    }
}
