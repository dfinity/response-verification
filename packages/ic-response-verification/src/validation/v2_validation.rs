use crate::types::Certification;
use ic_certification::hash_tree::HashTreeNode;
use ic_certification::{hash_tree::Sha256Digest, HashTree, Label, SubtreeLookupResult};

fn path_from_parts<T>(parts: &Vec<T>) -> Vec<Label>
where
    T: AsRef<[u8]>,
{
    let mut path = vec![Label::from("http_expr")];
    path.extend(parts.iter().map(Label::from));

    path
}

fn path_exists_in_tree(path: &Vec<Label>, tree: &HashTree) -> bool {
    match tree.lookup_subtree(path) {
        SubtreeLookupResult::Found(_) => true,
        _ => false,
    }
}

pub fn validate_expr_path(
    expr_path: &Vec<String>,
    request_url: &http::Uri,
    tree: &HashTree,
) -> bool {
    let mut request_url_parts = request_url
        .path()
        .split('/')
        .filter(|e| !e.is_empty())
        .collect::<Vec<_>>();

    let certified_path = path_from_parts(&expr_path);
    let mut request_url_path = path_from_parts(&request_url_parts);

    // if the expr_path matches the full URL, there can't be a more precise path in the tree
    request_url_path.push("<$>".into());
    if certified_path.eq(&request_url_path) {
        return true;
    }

    // if the expr_path does not match full URL and the full URL exists in the tree
    // then validation fails
    if path_exists_in_tree(&request_url_path, tree) {
        return false;
    }
    request_url_path.pop();

    // if the expr_path matches the full URL with a wildcard, there can't be a more precise path in the tree
    request_url_path.push("<*>".into());
    if certified_path.eq(&request_url_path) {
        return true;
    }

    // recursively check for partial URL matches with wildcards that are more precise than the expr_path
    while request_url_parts.len() >= expr_path.len() {
        let mut paths = path_from_parts(&request_url_parts);
        paths.push("<*>".into());

        if path_exists_in_tree(&paths, tree) {
            return false;
        }

        request_url_parts.pop();
    }

    return true;
}

pub fn validate_hashes(
    expr_hash: &Sha256Digest,
    request_hash: &Option<Sha256Digest>,
    response_hash: &Sha256Digest,
    expr_path: &Vec<String>,
    tree: &HashTree,
    certification: &Certification,
) -> bool {
    let mut path = path_from_parts(expr_path);
    path.push(expr_hash.into());

    let SubtreeLookupResult::Found(expr_tree) = tree.lookup_subtree(&path) else {
        return false;
    };

    let mut expr_tree_path: Vec<Label> = vec![];
    if let (Some(_), Some(request_hash)) = (&certification.request_certification, request_hash) {
        expr_tree_path.push(request_hash.into());
    }
    expr_tree_path.push(response_hash.into());

    match expr_tree.lookup_subtree(&expr_tree_path) {
        SubtreeLookupResult::Found(res_tree) => {
            HashTreeNode::from(res_tree).eq(&HashTreeNode::Empty())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_utils::{hex_decode, sha256_from_hex};
    use crate::types::{RequestCertification, ResponseCertification};
    use crate::{
        hash::hash,
        test_utils::test_utils::{create_pruned, remove_whitespace},
    };
    use ic_certification::hash_tree::{empty, fork, label};

    const REQUEST_HASH: &str = "5fac69685533f0650991441a2b818e8ad5ab2fec51de8cfdbea1276135494815";
    const RESPONSE_HASH: &str = "07b7c729f4083db0e266fef3f8f5acf1315135605bf38884c07ebb59fbf91ce8";
    const CEL_EXPRESSION: &str = r#"
        default_certification (
            ValidationArgs {
                certification: Certification {
                    request_certification: RequestCertification {
                        certified_request_headers: ["host"],
                        certified_query_parameters: []
                    },
                    response_certification: ResponseCertification {
                        certified_response_headers: ResponseHeaderList {
                            headers: ["Accept-Encoding", "Cache-Control"]
                        }
                    }
                }
            }
        )
    "#;

    #[test]
    fn validate_hashes_that_exist() {
        let expr_hash = hash(remove_whitespace(CEL_EXPRESSION).as_bytes());
        let request_hash = sha256_from_hex(REQUEST_HASH);
        let response_hash = sha256_from_hex(RESPONSE_HASH);
        let expr_path = vec!["assets".into(), "js".into(), "app.js".into(), "<$>".into()];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label("app.js", label("<$>", label(expr_hash, fork(
                            label(request_hash, label(response_hash, empty())),
                            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
                        )))),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );
        let certification = create_certification();

        let result = validate_hashes(
            &expr_hash,
            &Some(request_hash),
            &response_hash,
            &expr_path,
            &tree,
            &certification,
        );

        assert!(result);
    }

    #[test]
    fn validate_expr_hash_that_does_not_exist() {
        let expr_hash = hash(remove_whitespace(CEL_EXPRESSION).as_bytes());
        let request_hash = sha256_from_hex(REQUEST_HASH);
        let response_hash = sha256_from_hex(RESPONSE_HASH);
        let expr_path = vec!["assets".into(), "js".into(), "app.js".into(), "<$>".into()];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "css",
                        label(
                            "app.css",
                            label(
                                "<$>",
                                label(
                                    expr_hash,
                                    label(request_hash, label(response_hash, empty())),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );
        let certification = create_certification();

        let result = validate_hashes(
            &expr_hash,
            &Some(request_hash),
            &response_hash,
            &expr_path,
            &tree,
            &certification,
        );

        assert!(!result);
    }

    #[test]
    fn validate_expr_hash_that_does_not_match() {
        let expr_hash = hash(remove_whitespace(CEL_EXPRESSION).as_bytes());
        let request_hash = sha256_from_hex(REQUEST_HASH);
        let response_hash = sha256_from_hex(RESPONSE_HASH);
        let expr_path = vec!["assets".into(), "js".into(), "app.js".into(), "<$>".into()];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label(
                            "app.js",
                            label(
                                "<$>",
                                label(
                                    hex_decode("c5dbe9d11756d4a7b05e5c0e246035dedcd1e4e71bd1e726c4011940d811496b"),
                                    label(request_hash, label(response_hash, empty())),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );
        let certification = create_certification();

        let result = validate_hashes(
            &expr_hash,
            &Some(request_hash),
            &response_hash,
            &expr_path,
            &tree,
            &certification,
        );

        assert!(!result);
    }

    #[test]
    fn validate_req_hash_that_does_not_exist() {
        let expr_hash = hash(remove_whitespace(CEL_EXPRESSION).as_bytes());
        let request_hash = sha256_from_hex(REQUEST_HASH);
        let response_hash = sha256_from_hex(RESPONSE_HASH);
        let expr_path = vec!["assets".into(), "js".into(), "app.js".into(), "<$>".into()];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label(
                            "app.js",
                            label("<$>", label(expr_hash, label(response_hash, empty()))),
                        ),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );
        let certification = create_certification();

        let result = validate_hashes(
            &expr_hash,
            &Some(request_hash),
            &response_hash,
            &expr_path,
            &tree,
            &certification,
        );

        assert!(!result);
    }

    #[test]
    fn validate_req_hash_that_does_not_match() {
        let expr_hash = hash(remove_whitespace(CEL_EXPRESSION).as_bytes());
        let request_hash = sha256_from_hex(REQUEST_HASH);
        let response_hash = sha256_from_hex(RESPONSE_HASH);
        let expr_path = vec!["assets".into(), "js".into(), "app.js".into(), "<$>".into()];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label("app.js", label("<$>", label(expr_hash, fork(
                            label(sha256_from_hex("236baceb3bbf1ad861a981807c4f7580344d8c7b25b7329be266c603ccc0f03e"), label(response_hash, empty())),
                            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
                        )))),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );
        let certification = create_certification();

        let result = validate_hashes(
            &expr_hash,
            &Some(request_hash),
            &response_hash,
            &expr_path,
            &tree,
            &certification,
        );

        assert!(!result);
    }

    #[test]
    fn validate_res_hash_that_does_not_exist() {
        let expr_hash = hash(remove_whitespace(CEL_EXPRESSION).as_bytes());
        let request_hash = sha256_from_hex(REQUEST_HASH);
        let response_hash = sha256_from_hex(RESPONSE_HASH);
        let expr_path = vec!["assets".into(), "js".into(), "app.js".into(), "<$>".into()];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label("app.js", label("<$>", label(expr_hash, fork(
                            label(request_hash, empty()),
                            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
                        )))),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );
        let certification = create_certification();

        let result = validate_hashes(
            &expr_hash,
            &Some(request_hash),
            &response_hash,
            &expr_path,
            &tree,
            &certification,
        );

        assert!(!result);
    }

    #[test]
    fn validate_res_hash_that_does_not_match() {
        let expr_hash = hash(remove_whitespace(CEL_EXPRESSION).as_bytes());
        let request_hash = sha256_from_hex(REQUEST_HASH);
        let response_hash = sha256_from_hex(RESPONSE_HASH);
        let expr_path = vec!["assets".into(), "js".into(), "app.js".into(), "<$>".into()];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label("app.js", label("<$>", label(expr_hash, fork(
                            label(request_hash, label(sha256_from_hex("02456594f95f4e8f35f14850d23bc05aa065ecc17eb4aeaff3c1819edaee0816"), empty())),
                            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
                        )))),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );
        let certification = create_certification();

        let result = validate_hashes(
            &expr_hash,
            &Some(request_hash),
            &response_hash,
            &expr_path,
            &tree,
            &certification,
        );

        assert!(!result);
    }

    #[test]
    fn validate_expr_path_that_is_most_precise_path_available() {
        let expr_path = vec!["assets".into(), "js".into(), "app.js".into(), "<$>".into()];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label("js", label("app.js", label("<$>", empty()))),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, &request_uri, &tree);

        assert!(result);
    }

    #[test]
    fn validate_expr_path_that_does_not_exist() {
        let expr_path = vec!["assets".into(), "js".into(), "app.js".into(), "<$>".into()];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label("assets", label("js", label("<*>", empty()))),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, &request_uri, &tree);

        assert!(result);
    }

    #[test]
    fn validate_expr_path_that_has_more_precise_path_available() {
        let expr_path = vec!["assets".into(), "js".into(), "<*>".into()];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label("js", label("app.js", label("<$>", empty()))),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, &request_uri, &tree);

        assert!(!result);
    }

    #[test]
    fn validate_expr_path_that_has_more_precise_wildcard_path_available() {
        let expr_path = vec!["assets".into(), "<*>".into()];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label("assets", label("js", label("<*>", empty()))),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, &request_uri, &tree);

        assert!(!result);
    }

    fn create_certification() -> Certification {
        Certification {
            request_certification: Some(RequestCertification {
                certified_request_headers: vec!["Host".into()],
                certified_query_parameters: vec![],
            }),
            response_certification: ResponseCertification::CertifiedHeaders(vec![
                "Accept-Encoding".into(),
                "Cache-Control".into(),
            ]),
        }
    }
}
