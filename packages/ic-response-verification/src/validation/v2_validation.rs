use crate::{ResponseVerificationError, ResponseVerificationResult};
use ic_certification::hash_tree::HashTreeNode;
use ic_certification::{hash_tree::Hash, HashTree, Label, SubtreeLookupResult};
use ic_http_certification::cel::DefaultCelExpression;
use ic_http_certification::utils::{
    is_wildcard_path_valid_for_request_path, more_specific_wildcards_for,
    EXACT_PATH_TERMINATOR_BYTES, PATH_PREFIX_BYTES,
};
use ic_http_certification::CelExpression;

fn path_from_parts<T>(parts: &[T]) -> Vec<Vec<u8>>
where
    T: AsRef<[u8]>,
{
    parts.iter().map(|p| p.as_ref().to_vec()).collect()
}

fn path_might_exist_in_tree(path: &[Vec<u8>], tree: &HashTree) -> bool {
    !matches!(tree.lookup_subtree(path), SubtreeLookupResult::Absent)
}

fn path_exists_in_tree(path: &[Vec<u8>], tree: &HashTree) -> bool {
    matches!(tree.lookup_subtree(path), SubtreeLookupResult::Found(_))
}

fn expr_path_has_valid_suffix(expr_path: &[String]) -> bool {
    expr_path.ends_with(&["<$>".to_string()]) || expr_path.ends_with(&["<*>".to_string()])
}

fn expr_path_has_valid_prefix(expr_path: &[String]) -> bool {
    expr_path.starts_with(&["http_expr".to_string()])
}

pub fn validate_expr_path(
    expr_path: &[String],
    request_path: &str,
    tree: &HashTree,
) -> ResponseVerificationResult {
    if !expr_path_has_valid_prefix(expr_path) {
        return Err(ResponseVerificationError::UnexpectedExpressionPathPrefix {
            provided_expr_path: expr_path.to_vec(),
        });
    }

    if !expr_path_has_valid_suffix(expr_path) {
        return Err(ResponseVerificationError::UnexpectedExpressionPathSuffix {
            provided_expr_path: expr_path.to_vec(),
        });
    }

    let mut request_url_parts = vec!["http_expr"];
    request_url_parts.extend(request_path.split('/').filter(|e| !e.is_empty()));

    // make sure to treat a request for a directory and a file as different paths
    // i.e. /app is not the same as /app/
    // we do this by inserting an empty space for directory paths
    if request_path.ends_with('/') {
        request_url_parts.push("");
    }

    let original_path = path_from_parts(expr_path);
    let mut request_url_path = path_from_parts(&request_url_parts);

    // if the expr_path matches the full URL, there can't be a more precise path in the tree
    request_url_path.push("<$>".into());
    if original_path.eq(&request_url_path) {
        return if path_exists_in_tree(&original_path, tree) {
            Ok(())
        } else {
            Err(
                ResponseVerificationError::ExactExpressionPathNotFoundInTree {
                    provided_expr_path: expr_path.to_vec(),
                },
            )
        };
    }

    // at this point there are no more valid exact paths,
    // so validation fails if the certified_path ends with an exact path suffix,
    if original_path.ends_with(&[EXACT_PATH_TERMINATOR_BYTES.to_vec()]) {
        return Err(ResponseVerificationError::ExactExpressionPathMismatch {
            request_path: request_url_path
                .iter()
                .map(|e| String::from_utf8_lossy(e))
                .collect(),
            provided_expr_path: expr_path.to_vec(),
        });
    }

    // validation fails if the expr_path does not match full URL and the full URL might exist in the tree
    if path_might_exist_in_tree(&request_url_path, tree) {
        return Err(
            ResponseVerificationError::ExactExpressionPathMightExistInTree {
                potential_expr_path: request_url_path
                    .iter()
                    .map(|e| String::from_utf8_lossy(e).to_string())
                    .collect(),
                provided_expr_path: expr_path.to_vec(),
                request_path: request_path.to_string(),
            },
        );
    }
    request_url_path.pop(); // pop "<$>"

    let mut potential_path = original_path.clone();
    potential_path.pop(); // pop "<*>"

    if !is_wildcard_path_valid_for_request_path(&potential_path, &request_url_path) {
        return Err(ResponseVerificationError::WildcardExpressionPathMismatch {
            provided_expr_path: potential_path
                .iter()
                .map(|e| String::from_utf8_lossy(e).to_string())
                .collect(),
            request_path: request_path.to_string(),
        });
    }

    // recursively check for partial URL matches with wildcards that are more precise than the expr_path
    for wildcard_path in more_specific_wildcards_for(&request_url_path, &original_path).iter_mut() {
        wildcard_path.insert(0, PATH_PREFIX_BYTES.to_vec());

        if path_might_exist_in_tree(wildcard_path, tree) {
            return Err(
                ResponseVerificationError::MoreSpecificWildcardExpressionMightExistInTree {
                    provided_expr_path: expr_path.to_vec(),
                    more_specific_expr_path: wildcard_path
                        .iter()
                        .map(|e| String::from_utf8_lossy(e).to_string())
                        .collect(),
                    request_path: request_path.to_string(),
                },
            );
        }
    }

    // if we haven't found a more specific path in the tree,
    // then the provided path is valid if it exists in the tree
    if path_exists_in_tree(&original_path, tree) {
        Ok(())
    } else {
        Err(
            ResponseVerificationError::WildcardExpressionPathNotFoundInTree {
                provided_expr_path: expr_path.to_vec(),
                request_path: request_path.to_string(),
            },
        )
    }
}

pub fn validate_expr_hash(
    expr_path: &[String],
    expr_hash: &Hash,
    tree: &HashTree,
) -> Option<HashTree> {
    let mut path = path_from_parts(expr_path);
    path.push(expr_hash.into());

    match tree.lookup_subtree(&path) {
        SubtreeLookupResult::Found(expr_tree) => Some(expr_tree),
        _ => None,
    }
}

pub fn validate_hashes(
    expr_hash: &Hash,
    request_hash: &Option<Hash>,
    response_hash: &Hash,
    expr_path: &[String],
    tree: &HashTree,
    certification: &CelExpression,
) -> bool {
    let Some(expr_tree) = validate_expr_hash(expr_path, expr_hash, tree) else {
        return false;
    };

    let mut expr_tree_path: Vec<Label> = vec![];
    if let (CelExpression::Default(DefaultCelExpression::Full(_)), Some(request_hash)) =
        (&certification, request_hash)
    {
        expr_tree_path.push(request_hash.into());
    } else {
        expr_tree_path.push("".into());
    }
    expr_tree_path.push(response_hash.into());

    match expr_tree.lookup_subtree(&expr_tree_path) {
        SubtreeLookupResult::Found(res_tree) => {
            HashTreeNode::from(res_tree).eq(&HashTreeNode::Leaf("".as_bytes().to_vec()))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::{create_pruned, remove_whitespace, sha256_from_hex};
    use ic_certification::hash_tree::{fork, label, leaf};
    use ic_http_certification::{
        cel::{DefaultFullCelExpression, DefaultRequestCertification},
        DefaultResponseCertification,
    };
    use ic_representation_independent_hash::hash;
    use ic_response_verification_test_utils::hex_decode;

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
    fn validate_sibling_expr_hash() {
        let no_certification_expr_hash =
            hash(remove_whitespace(NO_CERTIFICATION_CEL_EXPRESSION).as_bytes());
        let expr_hash = hash(remove_whitespace(CEL_EXPRESSION).as_bytes());
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
                                fork(
                                    label(expr_hash, leaf("")),
                                    label(no_certification_expr_hash, leaf("")),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );

        let result = validate_expr_hash(&expr_path, &expr_hash, &tree);
        let no_certification_result =
            validate_expr_hash(&expr_path, &no_certification_expr_hash, &tree);

        assert_eq!(result, Some(leaf("")));
        assert_eq!(no_certification_result, Some(leaf("")));
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

        validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap();
    }

    #[test]
    fn validation_expr_path_with_trailing_slash() {
        let expr_path = vec!["http_expr".into(), "app".into(), "".into(), "<$>".into()];
        let request_uri = http::Uri::try_from("https://dapp.com/app/").unwrap();
        let tree = fork(
            label("http_expr", label("app", label("", label("<$>", leaf(""))))),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap();
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

        validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap();
    }

    #[test]
    fn validate_trailing_slash_wildcard_expr_path_that_is_most_precise_path_available() {
        let expr_path = vec!["http_expr".into(), "app".into(), "".into(), "<*>".into()];
        let request_uri = http::Uri::try_from("https://dapp.com/app/not-existing").unwrap();
        let tree = fork(
            label(
                "http_expr",
                label(
                    "app",
                    fork(label("", label("<*>", leaf(""))), label("<$>", leaf(""))),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap();
    }

    #[test]
    fn validate_trailing_slash_wildcard_expr_path_that_is_not_most_precise_path_available() {
        let expr_path = vec!["http_expr".into(), "".into(), "<*>".into()];
        let request_uri = http::Uri::try_from("https://dapp.com/app/not-existing").unwrap();
        let tree = fork(
            label(
                "http_expr",
                fork(
                    label(
                        "app",
                        fork(label("", label("<*>", leaf(""))), label("<$>", leaf(""))),
                    ),
                    label("", label("<*>", leaf(""))),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap_err();

        assert!(matches!(
            result,
            ResponseVerificationError::MoreSpecificWildcardExpressionMightExistInTree { .. }
        ));
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

        let result = validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap_err();

        assert!(matches!(
            result,
            ResponseVerificationError::ExactExpressionPathNotFoundInTree { .. }
        ));
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

        let result = validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap_err();

        assert!(matches!(
            result,
            ResponseVerificationError::ExactExpressionPathMismatch { .. }
        ));
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

        let result = validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap_err();

        assert!(matches!(
            result,
            ResponseVerificationError::WildcardExpressionPathMismatch { .. }
        ));
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

        let result = validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap_err();

        assert!(matches!(
            result,
            ResponseVerificationError::ExactExpressionPathMightExistInTree { .. }
        ));
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

        let result = validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap_err();

        assert!(matches!(
            result,
            ResponseVerificationError::ExactExpressionPathMightExistInTree { .. }
        ));
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

        let result = validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap_err();

        assert!(matches!(
            result,
            ResponseVerificationError::MoreSpecificWildcardExpressionMightExistInTree { .. }
        ));
    }

    #[test]
    fn validate_expr_path_that_does_not_begin_with_http_expr() {
        let expr_path = vec![
            "http_assets".into(),
            "assets".into(),
            "js".into(),
            "app.js".into(),
            "<$>".into(),
        ];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label(
                "http_assets",
                label(
                    "assets",
                    label("js", label("app.js", label("<$>", leaf("")))),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap_err();

        assert!(matches!(
            result,
            ResponseVerificationError::UnexpectedExpressionPathPrefix { .. }
        ));
    }

    #[test]
    fn validate_expr_path_that_does_not_end_with_valid_suffix() {
        let expr_path = vec!["http_expr".into(), "assets".into()];
        let request_uri = http::Uri::try_from("https://dapp.com/assets/js/app.js").unwrap();
        let tree = fork(
            label("http_expr", label("<*>", leaf(""))),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let result = validate_expr_path(&expr_path, request_uri.path(), &tree).unwrap_err();

        assert!(matches!(
            result,
            ResponseVerificationError::UnexpectedExpressionPathSuffix { .. }
        ));
    }

    #[test]
    fn validate_various_expr_paths() {
        let tree_a_b_slash = fork(
            label(
                "http_expr",
                fork(
                    fork(label("", label("<*>", leaf(""))), label("<*>", leaf(""))),
                    label(
                        "a",
                        fork(
                            fork(label("", label("<*>", leaf(""))), label("<*>", leaf(""))),
                            label(
                                "b",
                                fork(label("", label("<*>", leaf(""))), label("<*>", leaf(""))),
                            ),
                        ),
                    ),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let tree_a_b = fork(
            label(
                "http_expr",
                fork(
                    fork(label("", label("<*>", leaf(""))), label("<*>", leaf(""))),
                    label(
                        "a",
                        fork(
                            fork(label("", label("<*>", leaf(""))), label("<*>", leaf(""))),
                            label("b", label("<*>", leaf(""))),
                        ),
                    ),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let tree_a_slash = fork(
            label(
                "http_expr",
                fork(
                    fork(label("", label("<*>", leaf(""))), label("<*>", leaf(""))),
                    label(
                        "a",
                        fork(label("", label("<*>", leaf(""))), label("<*>", leaf(""))),
                    ),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let tree_a = fork(
            label(
                "http_expr",
                fork(
                    fork(label("", label("<*>", leaf(""))), label("<*>", leaf(""))),
                    label("a", label("<*>", leaf(""))),
                ),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let tree_slash = fork(
            label(
                "http_expr",
                fork(label("", label("<*>", leaf(""))), label("<*>", leaf(""))),
            ),
            create_pruned("c01f7c0681a684be0a016b800981951832b53d5ffb55c49c27f6e83f7d2749c3"),
        );

        let tree_star = label("http_expr", label("<*>", leaf("")));

        // validations that should be successful
        for (request_uri, mut path, tree) in [
            ("/a/b", vec!["a", "b", "<*>"], tree_a_b_slash.clone()),
            ("/a/b/", vec!["a", "b", "", "<*>"], tree_a_b_slash.clone()),
            ("/a/b", vec!["a", "b", "<*>"], tree_a_b.clone()),
            ("/a/b/", vec!["a", "b", "<*>"], tree_a_b.clone()),
            ("/a/b", vec!["a", "", "<*>"], tree_a_slash.clone()),
            ("/a/b/", vec!["a", "", "<*>"], tree_a_slash.clone()),
            ("/a/b", vec!["a", "<*>"], tree_a.clone()),
            ("/a/b/", vec!["a", "<*>"], tree_a.clone()),
            ("/a/b", vec!["", "<*>"], tree_slash.clone()),
            ("/a/b/", vec!["", "<*>"], tree_slash.clone()),
            ("/a/b", vec!["<*>"], tree_star.clone()),
            ("/a/b/", vec!["<*>"], tree_star.clone()),
            ("/", vec!["", "<*>"], tree_a_b_slash.clone()),
            ("/", vec!["<*>"], tree_star.clone()),
        ] {
            path.insert(0, "http_expr");
            let expr_path: Vec<String> = path.iter().map(|x| x.to_string()).collect();
            validate_expr_path(
                &expr_path,
                http::Uri::try_from(request_uri).unwrap().path(),
                &tree,
            )
            .unwrap();
        }

        // expression paths that are missing in the tree
        for (request_uri, mut path, tree) in [
            ("/a/b/", vec!["a", "b", "", "<*>"], tree_a_b.clone()),
            ("/a/b", vec!["a", "b", "<*>"], tree_a_slash.clone()),
            ("/a/b/", vec!["a", "b", "<*>"], tree_a_slash.clone()),
            ("/a/b/", vec!["a", "b", "", "<*>"], tree_a_slash.clone()),
            ("/a/b", vec!["a", "", "<*>"], tree_a.clone()),
            ("/a/b", vec!["a", "b", "<*>"], tree_a.clone()),
            ("/a/b/", vec!["a", "", "<*>"], tree_a.clone()),
            ("/a/b/", vec!["a", "b", "<*>"], tree_a.clone()),
            ("/a/b/", vec!["a", "b", "", "<*>"], tree_a.clone()),
            ("/a/b", vec!["a", "<*>"], tree_slash.clone()),
            ("/a/b", vec!["a", "", "<*>"], tree_slash.clone()),
            ("/a/b", vec!["a", "b", "<*>"], tree_slash.clone()),
            ("/a/b/", vec!["a", "<*>"], tree_slash.clone()),
            ("/a/b/", vec!["a", "", "<*>"], tree_slash.clone()),
            ("/a/b/", vec!["a", "b", "<*>"], tree_slash.clone()),
            ("/a/b/", vec!["a", "b", "", "<*>"], tree_slash.clone()),
            ("/a/b", vec!["", "<*>"], tree_star.clone()),
            ("/a/b", vec!["a", "<*>"], tree_star.clone()),
            ("/a/b", vec!["a", "", "<*>"], tree_star.clone()),
            ("/a/b", vec!["a", "b", "<*>"], tree_star.clone()),
            ("/a/b/", vec!["", "<*>"], tree_star.clone()),
            ("/a/b/", vec!["a", "<*>"], tree_star.clone()),
            ("/a/b/", vec!["a", "", "<*>"], tree_star.clone()),
            ("/a/b/", vec!["a", "b", "<*>"], tree_star.clone()),
            ("/a/b/", vec!["a", "b", "", "<*>"], tree_star.clone()),
            ("/", vec!["", "<*>"], tree_star.clone()),
        ] {
            path.insert(0, "http_expr");
            let expr_path: Vec<String> = path.iter().map(|x| x.to_string()).collect();
            let result = validate_expr_path(
                &expr_path,
                http::Uri::try_from(request_uri).unwrap().path(),
                &tree,
            )
            .unwrap_err();

            assert!(matches!(
                result,
                ResponseVerificationError::WildcardExpressionPathNotFoundInTree { .. }
            ));
        }

        // expression paths that are not the most precise in the tree
        for (request_uri, mut path, tree) in [
            ("/", vec!["<*>"], tree_a_b_slash.clone()),
            ("/a/b", vec!["a", "", "<*>"], tree_a_b_slash.clone()),
            ("/a/b/", vec!["a", "b", "<*>"], tree_a_b_slash.clone()),
            ("/a/b", vec!["a", "", "<*>"], tree_a_b.clone()),
            ("/a/b/", vec!["a", "", "<*>"], tree_a_b.clone()),
            ("/a/b", vec!["a", "<*>"], tree_a_slash.clone()),
            ("/a/b/", vec!["a", "<*>"], tree_a_slash.clone()),
            ("/a/b", vec!["", "<*>"], tree_a.clone()),
            ("/a/b/", vec!["", "<*>"], tree_a.clone()),
            ("/a/b", vec!["<*>"], tree_slash.clone()),
            ("/a/b/", vec!["<*>"], tree_slash.clone()),
        ] {
            path.insert(0, "http_expr");
            let expr_path: Vec<String> = path.iter().map(|x| x.to_string()).collect();
            let result = validate_expr_path(
                &expr_path,
                http::Uri::try_from(request_uri).unwrap().path(),
                &tree,
            )
            .unwrap_err();

            assert!(matches!(
                result,
                ResponseVerificationError::MoreSpecificWildcardExpressionMightExistInTree { .. }
            ));
        }

        // expression paths that are not valid for the request path
        for (request_uri, mut path, tree) in [
            ("/", vec!["a", "<*>"], tree_a_b_slash.clone()),
            ("/a/b", vec!["a", "c", "<*>"], tree_a_b_slash.clone()),
            ("/a/b", vec!["c", "b", "<*>"], tree_a_b_slash.clone()),
        ] {
            path.insert(0, "http_expr");
            let expr_path: Vec<String> = path.iter().map(|x| x.to_string()).collect();
            let result = validate_expr_path(
                &expr_path,
                http::Uri::try_from(request_uri).unwrap().path(),
                &tree,
            )
            .unwrap_err();

            assert!(matches!(
                result,
                ResponseVerificationError::WildcardExpressionPathMismatch { .. }
            ));
        }
    }

    fn create_certification<'a>() -> CelExpression<'a> {
        CelExpression::Default(DefaultCelExpression::Full(DefaultFullCelExpression {
            request: DefaultRequestCertification::new(vec!["Host"], vec![]),
            response: DefaultResponseCertification::certified_response_headers(vec![
                "Accept-Encoding",
                "Cache-Control",
            ]),
        }))
    }
}
