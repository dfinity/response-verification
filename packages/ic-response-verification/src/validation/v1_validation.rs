use ic_certification::{hash_tree::Hash, HashTree, LookupResult};

pub fn validate_body(tree: &HashTree, request_path: &str, body_sha: &Hash) -> bool {
    let asset_path = ["http_assets".as_bytes(), request_path.as_bytes()];
    let index_fallback_path = ["http_assets".as_bytes(), "/index.html".as_bytes()];

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

    body_sha == tree_sha
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{create_tree, CreateTreeOptions};
    use http::Uri;
    use ic_representation_independent_hash::hash;

    static CANISTER_ID: &str = "r7inp-6aaaa-aaaaa-aaabq-cai";

    #[test]
    fn validate_body_with_matching_sha() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = hash(body);
        let uri = format!("https://ic0.dev/app.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .unwrap();
        let tree_options = CreateTreeOptions {
            path: Some(uri.path()),
            body_sha: Some(&body_sha),
        };
        let tree = create_tree(Some(tree_options));

        let result = validate_body(&tree, uri.path(), &body_sha);

        assert!(result);
    }

    /// This is a strange fallback, but it is necessary for SPA routing at the moment.
    /// https://internetcomputer.org/docs/current/references/ic-interface-spec/#http-gateway-certification
    ///
    /// It may be possible to remove this with a combination of asset canister redirect rules and v2 response verification.
    #[test]
    fn validate_body_with_index_fallback() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = hash(body);
        let uri = format!("https://ic0.dev/garbage.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .unwrap();
        let tree_options = CreateTreeOptions {
            path: Some("/index.html"),
            body_sha: Some(&body_sha),
        };
        let tree = create_tree(Some(tree_options));

        let result = validate_body(&tree, uri.path(), &body_sha);

        assert!(result);
    }

    #[test]
    fn validate_body_without_index_fallback() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = hash(body);
        let uri = format!("https://ic0.dev/app.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .unwrap();
        let tree_options = CreateTreeOptions {
            path: Some("/index.html"),
            body_sha: Some(&[9, 8, 7, 6, 5, 4, 3, 2, 1]),
        };
        let tree = create_tree(Some(tree_options));

        let result = validate_body(&tree, uri.path(), &body_sha);

        assert!(!result);
    }

    #[test]
    fn validate_body_without_matching_sha() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = hash(body);
        let uri = format!("https://ic0.dev/app.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .unwrap();
        let tree_options = CreateTreeOptions {
            path: Some(uri.path()),
            body_sha: Some(&[9, 8, 7, 6, 5, 4, 3, 2, 1]),
        };
        let tree = create_tree(Some(tree_options));

        let result = validate_body(&tree, uri.path(), &body_sha);

        assert!(!result);
    }

    #[test]
    fn validate_body_without_any_matching_path() {
        let body: &[u8] = &[1, 2, 3, 4, 5, 6];
        let body_sha = hash(body);
        let uri = format!("https://ic0.dev/app.js?canisterId={}", CANISTER_ID)
            .parse::<Uri>()
            .unwrap();
        let tree_options = CreateTreeOptions {
            path: Some("/garbage.js"),
            body_sha: Some(&body_sha),
        };
        let tree = create_tree(Some(tree_options));

        let result = validate_body(&tree, uri.path(), &body_sha);

        assert!(!result);
    }
}
