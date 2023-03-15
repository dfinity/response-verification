use crate::types::Certification;
use ic_certification::hash_tree::HashTreeNode;
use ic_certification::{hash_tree::Sha256Digest, HashTree, Label, SubtreeLookupResult};
use std::borrow::Cow;

fn path_from_parts<T>(parts: &[T]) -> Vec<Label>
where
    T: AsRef<[u8]>,
{
    parts.iter().map(Label::from).collect()
}

fn path_might_exist_in_tree(path: &Vec<Label>, tree: &HashTree) -> bool {
    !matches!(tree.lookup_subtree(path), SubtreeLookupResult::Absent)
}

pub fn validate_expr_path(expr_path: &[String], request_url: &http::Uri, tree: &HashTree) -> bool {
    let mut request_url_parts = vec!["http_expr"];
    request_url_parts.extend(request_url.path().split('/').filter(|e| !e.is_empty()));

    // make sure to treat a request for a directory and a file as different paths
    // i.e. /app is not the same as /app/
    // we do this by inserting an empty space for directory paths
    if request_url.path().ends_with('/') {
        request_url_parts.push("");
    }

    let mut certified_path = path_from_parts(expr_path);
    let mut request_url_path = path_from_parts(&request_url_parts);

    // if the expr_path matches the full URL, there can't be a more precise path in the tree
    request_url_path.push("<$>".into());
    if certified_path.eq(&request_url_path) {
        return true;
    }

    // at this point there are no more valid exact paths,
    // so if the certified_path ends with an exact path delimiter,
    // validation fails
    if certified_path.ends_with(&[Label::from("<$>")]) {
        return false;
    }

    // if the expr_path does not match full URL and the full URL exists in the tree
    // then validation fails
    if path_might_exist_in_tree(&request_url_path, tree) {
        return false;
    }
    request_url_path.pop(); // pop "<$>"

    // if the expr_path matches the full URL with a wildcard, there can't be a more precise path in the tree
    request_url_path.push("<*>".into());
    if certified_path.eq(&request_url_path) {
        return true;
    }
    request_url_path.pop(); // pop "<*>"
    certified_path.pop(); // pop "<*>"

    // recursively check for partial URL matches with wildcards that are more precise than the expr_path
    while request_url_path.len() > certified_path.len() {
        request_url_path.push("<*>".into());

        if path_might_exist_in_tree(&request_url_path, tree) {
            return false;
        }

        request_url_path.pop(); // pop "<*>"
        request_url_path.pop(); // pop the last segment of the path
    }

    // once we have reduced the request URL to the same size as the certified path,
    // we expect them to be equal, otherwise the provided_path is not valid
    certified_path.eq(&request_url_path)
}

pub fn validate_expr_hash<'a>(
    expr_path: &[String],
    expr_hash: &Sha256Digest,
    tree: &'a HashTree,
) -> Option<HashTree<'a>> {
    let mut path = path_from_parts(expr_path);
    path.push(expr_hash.into());

    match tree.lookup_subtree(&path) {
        SubtreeLookupResult::Found(expr_tree) => Some(expr_tree),
        _ => None,
    }
}

pub fn validate_hashes(
    expr_hash: &Sha256Digest,
    request_hash: &Option<Sha256Digest>,
    response_hash: &Sha256Digest,
    expr_path: &[String],
    tree: &HashTree,
    certification: &Certification,
) -> bool {
    let Some(expr_tree) = validate_expr_hash(expr_path, expr_hash, tree) else {
        return false;
    };

    let mut expr_tree_path: Vec<Label> = vec![];
    if let (Some(_), Some(request_hash)) = (&certification.request_certification, request_hash) {
        expr_tree_path.push(request_hash.into());
    } else {
        expr_tree_path.push("".into());
    }
    expr_tree_path.push(response_hash.into());

    match expr_tree.lookup_subtree(&expr_tree_path) {
        SubtreeLookupResult::Found(res_tree) => {
            HashTreeNode::from(res_tree).eq(&HashTreeNode::Leaf(Cow::from("".as_bytes())))
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
    use ic_certification::hash_tree::{fork, label, leaf};

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
    const NO_CERTIFICATION_CEL_EXPRESSION: &str = r#"
        default_certification (
            ValidationArgs {
                no_certification: Empty {}
            }
        )
    "#;

    #[test]
    fn validate_hashes_that_exist() {
        let expr_hash = hash(remove_whitespace(CEL_EXPRESSION).as_bytes());
        let request_hash = sha256_from_hex(REQUEST_HASH);
        let response_hash = sha256_from_hex(RESPONSE_HASH);
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "app.js".into(),
            "<$>".into(),
        ];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label("app.js", label("<$>", label(expr_hash, fork(
                            label(request_hash, label(response_hash, leaf(""))),
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
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "app.js".into(),
            "<$>".into(),
        ];
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
                                    label(request_hash, label(response_hash, leaf(""))),
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
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "app.js".into(),
            "<$>".into(),
        ];
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
                                    label(request_hash, label(response_hash, leaf(""))),
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
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "app.js".into(),
            "<$>".into(),
        ];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label(
                            "app.js",
                            label("<$>", label(expr_hash, label(response_hash, leaf("")))),
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
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "app.js".into(),
            "<$>".into(),
        ];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label("app.js", label("<$>", label(expr_hash, fork(
                            label(sha256_from_hex("236baceb3bbf1ad861a981807c4f7580344d8c7b25b7329be266c603ccc0f03e"), label(response_hash, leaf(""))),
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
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "app.js".into(),
            "<$>".into(),
        ];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label("app.js", label("<$>", label(expr_hash, fork(
                            label(request_hash, leaf("")),
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
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "app.js".into(),
            "<$>".into(),
        ];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label("app.js", label("<$>", label(expr_hash, fork(
                            label(request_hash, label(sha256_from_hex("02456594f95f4e8f35f14850d23bc05aa065ecc17eb4aeaff3c1819edaee0816"), leaf(""))),
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
    fn validate_expr_hash_no_certification() {
        let expr_hash = hash(remove_whitespace(NO_CERTIFICATION_CEL_EXPRESSION).as_bytes());
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "app.js".into(),
            "<$>".into(),
        ];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label("app.js", label("<$>", label(expr_hash, leaf("")))),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );

        let result = validate_expr_hash(&expr_path, &expr_hash, &tree);

        assert_eq!(result, Some(leaf("")));
    }

    #[test]
    fn validate_expr_hash_does_not_exist() {
        let expr_hash = hash(remove_whitespace(NO_CERTIFICATION_CEL_EXPRESSION).as_bytes());
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "app.js".into(),
            "<$>".into(),
        ];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label("app.js", label("<$>", label(sha256_from_hex("02456594f95f4e8f35f14850d23bc05aa065ecc17eb4aeaff3c1819edaee0816"), leaf("")))),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );

        let result = validate_expr_hash(&expr_path, &expr_hash, &tree);

        assert!(result.is_none());
    }

    #[test]
    fn validate_expr_path_that_is_most_precise_path_available() {
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "app.js".into(),
            "<$>".into(),
        ];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label("js", label("app.js", label("<$>", leaf("")))),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, &request_uri, &tree);

        assert!(result);
    }

    #[test]
    fn validation_expr_path_with_trailing_slash() {
        let expr_path = vec!["http_expr".into(), "app".into(), "".into(), "<$>".into()];
        let request_uri = http::Uri::try_from("https://dapp.com/app/").unwrap();
        let tree = fork(
            label("http_expr", label("app", label("", label("<$>", leaf(""))))),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, &request_uri, &tree);

        assert!(result);
    }

    #[test]
    fn validate_wildcard_expr_path_that_is_most_precise_path_available() {
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "<*>".into(),
        ];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label("assets", label("js", label("<*>", leaf("")))),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, &request_uri, &tree);

        assert!(result);
    }

    #[test]
    fn validate_expr_path_that_does_not_exist() {
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "app.js".into(),
            "<$>".into(),
        ];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label("assets", label("js", label("<*>", leaf("")))),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, &request_uri, &tree);

        assert!(result);
    }

    #[test]
    fn validate_expr_path_that_exists_but_does_not_match_request() {
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "<$>".into(),
        ];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label("assets", label("js", label("<$>", leaf("")))),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, &request_uri, &tree);

        assert!(!result);
    }

    #[test]
    fn validate_expr_path_that_does_not_match_request_but_exists() {
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "css".into(),
            "<*>".into(),
        ];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    fork(
                        label("js", label("<*>", leaf(""))),
                        label("css", label("<*>", leaf(""))),
                    ),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, &request_uri, &tree);

        assert!(!result);
    }

    #[test]
    fn validate_expr_path_where_more_specific_path_is_pruned() {
        let expr_path = vec!["http_expr".into(), "assets".into(), "<*>".into()];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    fork(
                        label("<*>", leaf("")),
                        create_pruned(
                            "c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3",
                        ),
                    ),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, &request_uri, &tree);

        assert!(!result);
    }

    #[test]
    fn validate_expr_path_that_has_more_precise_path_available() {
        let expr_path = vec![
            "http_expr".into(),
            "assets".into(),
            "js".into(),
            "<*>".into(),
        ];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label("js", label("app.js", label("<$>", leaf("")))),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, &request_uri, &tree);

        assert!(!result);
    }

    #[test]
    fn validate_expr_path_that_has_more_precise_wildcard_path_available() {
        let expr_path = vec!["http_expr".into(), "assets".into(), "<*>".into()];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label("assets", label("js", label("<*>", leaf("")))),
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
