use ic_certification::hash_tree::HashTreeNode;
use ic_certification::{hash_tree::Sha256Digest, hash_tree::SubtreeLookupResult, HashTree, Label};

pub fn validate_expr_hash(
    expr_hash: &Sha256Digest,
    expr_path: &Vec<String>,
    tree: &HashTree,
) -> bool {
    let mut path = vec![Label::from("http_expr")];
    path.extend(expr_path.iter().map(Label::from));

    match tree.lookup_subtree(&path) {
        SubtreeLookupResult::Found(HashTreeNode::Labeled(found_expr_hash, _)) => {
            expr_hash.eq(found_expr_hash.as_bytes())
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::test_utils::hex_decode;
    use crate::{
        hash::hash,
        test_utils::test_utils::{create_pruned, remove_whitespace},
    };
    use ic_certification::hash_tree::{empty, fork, label};

    const CEL_EXPRESSION: &str = r#"
        default_certification (
            ValidationArgs {
                certification: Certification {
                    no_request_certification: Empty {},
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
    fn validate_expr_hash_that_exists() {
        let expr_hash = hash(remove_whitespace(CEL_EXPRESSION).as_bytes());
        let expr_path = vec!["assets".into(), "js".into(), "app.js".into(), "<$>".into()];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "js",
                        label("app.js", label("<$>", label(expr_hash, empty()))),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );

        let result = validate_expr_hash(&expr_hash, &expr_path, &tree);

        assert!(result);
    }

    #[test]
    fn validate_expr_hash_that_does_not_exist() {
        let expr_hash = hash(remove_whitespace(CEL_EXPRESSION).as_bytes());
        let expr_path = vec!["assets".into(), "js".into(), "app.js".into(), "<$>".into()];
        let tree = fork(
            label(
                "http_expr",
                label(
                    "assets",
                    label(
                        "css",
                        label("app.css", label("<$>", label(expr_hash, empty()))),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );

        let result = validate_expr_hash(&expr_hash, &expr_path, &tree);

        assert!(!result);
    }

    #[test]
    fn validate_expr_hash_that_does_not_match() {
        let expr_hash = hash(remove_whitespace(CEL_EXPRESSION).as_bytes());
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
                                    empty()
                                )
                            )
                        ),
                    ),
                ),
            ),
            create_pruned("ea7fd1a6b0cac1fe118016ca3026e58d5ae67a6965478acb561edba542732e24"),
        );

        let result = validate_expr_hash(&expr_hash, &expr_path, &tree);

        assert!(!result);
    }
}
