use super::{
    certification_tree_entry::HttpCertificationTreeEntry,
    certification_tree_path::CertificationTreePathSegment,
};
use crate::{
    tree::HttpCertificationPathType,
    utils::{more_specific_wildcards_for, PATH_PREFIX_BYTES},
    HttpCertificationError, HttpCertificationPath, HttpCertificationResult,
};
use ic_certification::{labeled, labeled_hash, merge_hash_trees, AsHashTree, HashTree, NestedTree};
use ic_representation_independent_hash::Sha256Digest;

type CertificationTree = NestedTree<CertificationTreePathSegment, Vec<u8>>;

/// A certification tree for generic HTTP requests.
#[derive(Debug, Clone)]
pub struct HttpCertificationTree {
    tree: CertificationTree,
}

impl Default for HttpCertificationTree {
    fn default() -> Self {
        Self::new(CertificationTree::default())
    }
}

impl HttpCertificationTree {
    /// Creates a new empty [HttpCertificationTree] from a given [CertificationTree](ic_certification::NestedTree).
    /// The [default](HttpCertificationTree::default) implementation should be used in most cases.
    pub fn new(tree: CertificationTree) -> Self {
        Self { tree }
    }

    /// Returns the root hash of the tree.
    /// This hash can be used as the canister's certified variable.
    pub fn root_hash(&self) -> Sha256Digest {
        labeled_hash(PATH_PREFIX_BYTES, &self.tree.root_hash())
    }

    /// Inserts a given [HttpCertificationTreeEntry] into the tree.
    /// After performing this operation, the canister's certified variable will need to be updated
    /// with the new [root hash](HttpCertificationTree::root_hash) of the tree.
    pub fn insert(&mut self, entry: &HttpCertificationTreeEntry) {
        let tree_path = entry.to_tree_path();
        self.tree.insert(&tree_path, vec![]);
    }

    /// Deletes a given [HttpCertificationTreeEntry] from the tree.
    /// After performing this operation, the canister's certified variable will need to be updated
    /// with the new [root hash](HttpCertificationTree::root_hash) of the tree.
    pub fn delete(&mut self, entry: &HttpCertificationTreeEntry) {
        let tree_path = entry.to_tree_path();
        self.tree.delete(&tree_path);
    }

    /// Returns a pruned [HashTree] that will prove the presence of a given [HttpCertificationTreeEntry]
    /// in the full [HttpCertificationTree], without needing to return the full tree.
    ///
    /// `request_url` is required so that the witness can be generated with respect to the request URL.
    pub fn witness(
        &self,
        entry: &HttpCertificationTreeEntry,
        request_url: &str,
    ) -> HttpCertificationResult<HashTree> {
        let witness = match entry.path.get_type() {
            HttpCertificationPathType::Exact(_) => self.tree.witness(&entry.to_tree_path()),

            HttpCertificationPathType::Wildcard(wildcard_path) => {
                let requested_tree_path = HttpCertificationPath::exact(request_url).to_tree_path();
                let responding_tree_path = entry.path.to_tree_path();

                if responding_tree_path.len() > requested_tree_path.len() {
                    return Err(HttpCertificationError::WildcardPathNotValidForRequestPath {
                        wildcard_path: wildcard_path.to_string(),
                        request_path: request_url.to_string(),
                    });
                }

                // For wildcards we start by witnessing the path that was requested so the verifier can be sure
                // that there is no exact match in the tree.
                let witness = self.tree.witness(&requested_tree_path);

                // Then we witness the wildcard path that we will be responding with.
                let witness = merge_hash_trees(witness, self.tree.witness(&responding_tree_path));

                // Then we need to prove that there is not a more specific wildcard in the tree that
                // matches the request URL.
                more_specific_wildcards_for(&requested_tree_path, &responding_tree_path)
                    .iter()
                    .fold(witness, |acc, path| {
                        merge_hash_trees(acc, self.tree.witness(path))
                    })
            }
        };

        Ok(labeled(PATH_PREFIX_BYTES, witness))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        DefaultCelBuilder, DefaultResponseCertification, HttpCertification, HttpRequest,
        HttpResponse,
    };
    use ic_certification::SubtreeLookupResult;
    use rstest::*;

    #[rstest]
    fn test_witness() {
        let mut tree = HttpCertificationTree::default();

        let cel_expr = DefaultCelBuilder::full_certification()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build();

        let not_found_request = HttpRequest {
            url: "/assets/js/not-found.js".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: vec![],
        };
        let not_found_response = HttpResponse {
            status_code: 400,
            body: br#"404 Not Found"#.to_vec(),
            headers: vec![("IC-CertificateExpression".into(), cel_expr.to_string())],
            upgrade: None,
        };

        let hello_world_request = HttpRequest {
            url: "/assets/js/hello-world.js".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: vec![],
        };
        let hello_world_response = HttpResponse {
            status_code: 200,
            body: br#"console.log("Hello, World!")"#.to_vec(),
            headers: vec![("IC-CertificateExpression".into(), cel_expr.to_string())],
            upgrade: None,
        };

        let not_found_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::wildcard("/assets/js"),
            HttpCertification::full(&cel_expr, &not_found_request, &not_found_response, None)
                .unwrap(),
        );
        tree.insert(&not_found_entry);

        let hello_world_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact(&hello_world_request.url),
            HttpCertification::full(&cel_expr, &hello_world_request, &hello_world_response, None)
                .unwrap(),
        );
        tree.insert(&hello_world_entry);

        let not_found_witness = tree.witness(&not_found_entry, "/assets/js/0.js").unwrap();

        assert_eq!(
            not_found_witness.lookup_subtree(["http_expr", "<*>"]),
            SubtreeLookupResult::Absent
        );
        assert_eq!(
            not_found_witness.lookup_subtree(["http_expr", "", "<*>"]),
            SubtreeLookupResult::Absent
        );
        assert_eq!(
            not_found_witness.lookup_subtree(["http_expr", "assets", "<*>"]),
            SubtreeLookupResult::Absent
        );
        assert_eq!(
            not_found_witness.lookup_subtree(["http_expr", "assets", "", "<*>"]),
            SubtreeLookupResult::Absent
        );
        assert!(matches!(
            not_found_witness.lookup_subtree(["http_expr", "assets", "js", "<*>"]),
            SubtreeLookupResult::Found(_)
        ));
        assert_eq!(
            not_found_witness.lookup_subtree(["http_expr", "assets", "js", "0.js", "<*>"]),
            SubtreeLookupResult::Absent
        );

        let hello_world_witness = tree
            .witness(&hello_world_entry, "/assets/js/hello-world.js")
            .unwrap();

        assert!(matches!(
            hello_world_witness.lookup_subtree([
                "http_expr",
                "assets",
                "js",
                "hello-world.js",
                "<$>"
            ]),
            SubtreeLookupResult::Found(_)
        ));
    }

    #[rstest]
    fn delete_removes_empty_subpaths() {
        let mut http_tree = HttpCertificationTree::default();
        let cel_expr = DefaultCelBuilder::full_certification()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build();
        let req_url = "/assets/js/hello-world.js";

        // arrange four paths in the tree,
        // two requests, with two responses each
        //
        // The tree should look like this:
        // -- "assets" -- "js" -- "hello-world.js"
        //                              |-- ${cel_expr_hash}
        //                                  |-- ${get_request_hash}
        //                                  |   |-- ${response_hash}
        //                                  |   |-- ${alt_response_hash}
        //                                  |-- ${post_request_hash}
        //                                      |-- ${response_hash}
        //                                      |-- ${alt_response_hash}
        //
        // Resulting in the following paths (number labels are referenced in comments below):
        // (1) "assets" -- "js" -- "hello-world.js" -- ${cel_expr_hash} -- ${get_request_hash} -- ${response_hash}
        // (2) "assets" -- "js" -- "hello-world.js" -- ${cel_expr_hash} -- ${get_request_hash} -- ${alt_response_hash}
        // (3) "assets" -- "js" -- "hello-world.js" -- ${cel_expr_hash} -- ${post_request_hash} -- ${response_hash}
        // (4) "assets" -- "js" -- "hello-world.js" -- ${cel_expr_hash} -- ${post_request_hash} -- ${alt_response_hash}

        let get_request = HttpRequest {
            url: req_url.to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: vec![],
        };
        let post_request = HttpRequest {
            url: req_url.to_string(),
            method: "POST".to_string(),
            headers: vec![],
            body: vec![],
        };

        let response = HttpResponse {
            status_code: 200,
            body: br#"console.log("Hello, World!")"#.to_vec(),
            headers: vec![("IC-CertificateExpression".into(), cel_expr.to_string())],
            upgrade: None,
        };
        let alt_response = HttpResponse {
            status_code: 200,
            body: br#"console.log("Hello, ALT World!")"#.to_vec(),
            headers: vec![("IC-CertificateExpression".into(), cel_expr.to_string())],
            upgrade: None,
        };

        let get_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact(&get_request.url),
            HttpCertification::full(&cel_expr, &get_request, &response, None).unwrap(),
        );
        http_tree.insert(&get_entry);

        let post_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact(&post_request.url),
            HttpCertification::full(&cel_expr, &post_request, &response, None).unwrap(),
        );
        http_tree.insert(&post_entry);

        let alt_get_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact(&get_request.url),
            HttpCertification::full(&cel_expr, &get_request, &alt_response, None).unwrap(),
        );
        http_tree.insert(&alt_get_entry);

        let alt_post_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact(&post_request.url),
            HttpCertification::full(&cel_expr, &post_request, &alt_response, None).unwrap(),
        );
        http_tree.insert(&alt_post_entry);

        assert!(matches!(
            http_tree
                .witness(&get_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&get_entry)),
            SubtreeLookupResult::Found(_)
        ));
        assert!(matches!(
            http_tree
                .witness(&post_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&post_entry)),
            SubtreeLookupResult::Found(_)
        ));
        assert!(matches!(
            http_tree
                .witness(&alt_get_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&alt_get_entry)),
            SubtreeLookupResult::Found(_)
        ));
        assert!(matches!(
            http_tree
                .witness(&alt_post_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&alt_post_entry)),
            SubtreeLookupResult::Found(_)
        ));

        assert!(http_tree
            .tree
            .contains_path(&HttpCertificationPath::exact(req_url).to_tree_path()));
        assert!(http_tree.tree.contains_path(&get_entry.to_tree_path()));
        assert!(http_tree.tree.contains_path(&post_entry.to_tree_path()));
        assert!(http_tree.tree.contains_path(&alt_get_entry.to_tree_path()));
        assert!(http_tree.tree.contains_path(&alt_post_entry.to_tree_path()));

        // delete the (1) path, all other paths should remain in the tree
        http_tree.delete(&get_entry);

        assert!(matches!(
            http_tree
                .witness(&get_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&get_entry)),
            SubtreeLookupResult::Absent
        ));
        assert!(matches!(
            http_tree
                .witness(&post_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&post_entry)),
            SubtreeLookupResult::Found(_)
        ));
        assert!(matches!(
            http_tree
                .witness(&alt_get_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&alt_get_entry)),
            SubtreeLookupResult::Found(_)
        ));
        assert!(matches!(
            http_tree
                .witness(&alt_post_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&alt_post_entry)),
            SubtreeLookupResult::Found(_)
        ));

        assert!(http_tree
            .tree
            .contains_path(&HttpCertificationPath::exact(req_url).to_tree_path()));
        assert!(!http_tree.tree.contains_path(&get_entry.to_tree_path()));
        assert!(http_tree.tree.contains_path(&post_entry.to_tree_path()));
        assert!(http_tree.tree.contains_path(&alt_get_entry.to_tree_path()));
        assert!(http_tree.tree.contains_path(&alt_post_entry.to_tree_path()));

        // delete the (3) path, now only (2) and (4) should remain in the tree
        http_tree.delete(&post_entry);

        assert!(matches!(
            http_tree
                .witness(&get_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&get_entry)),
            SubtreeLookupResult::Absent
        ));
        assert!(matches!(
            http_tree
                .witness(&post_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&post_entry)),
            SubtreeLookupResult::Absent
        ));
        assert!(matches!(
            http_tree
                .witness(&alt_get_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&alt_get_entry)),
            SubtreeLookupResult::Found(_)
        ));
        assert!(matches!(
            http_tree
                .witness(&alt_post_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&alt_post_entry)),
            SubtreeLookupResult::Found(_)
        ));

        assert!(http_tree
            .tree
            .contains_path(&HttpCertificationPath::exact(req_url).to_tree_path()));
        assert!(!http_tree.tree.contains_path(&get_entry.to_tree_path()));
        assert!(!http_tree.tree.contains_path(&post_entry.to_tree_path()));
        assert!(http_tree.tree.contains_path(&alt_get_entry.to_tree_path()));
        assert!(http_tree.tree.contains_path(&alt_post_entry.to_tree_path()));

        // delete the (2) path, now only (4) should remain in the tree
        http_tree.delete(&alt_get_entry);

        assert!(matches!(
            http_tree
                .witness(&get_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&get_entry)),
            SubtreeLookupResult::Absent
        ));
        assert!(matches!(
            http_tree
                .witness(&post_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&post_entry)),
            SubtreeLookupResult::Absent
        ));
        assert!(matches!(
            http_tree
                .witness(&alt_get_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&alt_get_entry)),
            SubtreeLookupResult::Absent
        ));
        assert!(matches!(
            http_tree
                .witness(&alt_post_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&alt_post_entry)),
            SubtreeLookupResult::Found(_)
        ));

        assert!(http_tree
            .tree
            .contains_path(&HttpCertificationPath::exact(req_url).to_tree_path()));
        assert!(!http_tree.tree.contains_path(&get_entry.to_tree_path()));
        assert!(!http_tree.tree.contains_path(&post_entry.to_tree_path()));
        assert!(!http_tree.tree.contains_path(&alt_get_entry.to_tree_path()));
        assert!(http_tree.tree.contains_path(&alt_post_entry.to_tree_path()));

        // delete the (4) path, now the tree should be empty
        http_tree.delete(&alt_post_entry);

        assert!(matches!(
            http_tree
                .witness(&get_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&get_entry)),
            SubtreeLookupResult::Absent
        ));
        assert!(matches!(
            http_tree
                .witness(&post_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&post_entry)),
            SubtreeLookupResult::Absent
        ));
        assert!(matches!(
            http_tree
                .witness(&alt_get_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&alt_get_entry)),
            SubtreeLookupResult::Absent
        ));
        assert!(matches!(
            http_tree
                .witness(&alt_post_entry, req_url)
                .unwrap()
                .lookup_subtree(&lookup_path_from_entry(&alt_post_entry)),
            SubtreeLookupResult::Absent
        ));

        assert!(!http_tree
            .tree
            .contains_path(&HttpCertificationPath::exact(req_url).to_tree_path()));
        assert!(!http_tree.tree.contains_path(&get_entry.to_tree_path()));
        assert!(!http_tree.tree.contains_path(&post_entry.to_tree_path()));
        assert!(!http_tree.tree.contains_path(&alt_get_entry.to_tree_path()));
        assert!(!http_tree.tree.contains_path(&alt_post_entry.to_tree_path()));
    }

    #[rstest]
    fn test_witness_wildcard_too_long() {
        let mut tree = HttpCertificationTree::default();

        let cel_expr = DefaultCelBuilder::full_certification()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build();

        let not_found_request = HttpRequest {
            url: "/assets/js/not-found.js".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: vec![],
        };
        let not_found_response = HttpResponse {
            status_code: 400,
            body: br#"404 Not Found"#.to_vec(),
            headers: vec![("IC-CertificateExpression".into(), cel_expr.to_string())],
            upgrade: None,
        };

        let not_found_entry = HttpCertificationTreeEntry::new(
            HttpCertificationPath::wildcard("/assets/js"),
            HttpCertification::full(&cel_expr, &not_found_request, &not_found_response, None)
                .unwrap(),
        );
        tree.insert(&not_found_entry);

        let witness = tree.witness(&not_found_entry, "/assets");

        assert!(matches!(
            witness,
            Err(HttpCertificationError::WildcardPathNotValidForRequestPath { .. })
        ));
    }

    #[rstest]
    fn test_witness_wildcard_matches_asset() {
        let mut tree = HttpCertificationTree::default();

        let cel_expr = DefaultCelBuilder::full_certification()
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build();

        let index_html_request = HttpRequest {
            url: "/".to_string(),
            method: "GET".to_string(),
            headers: vec![],
            body: vec![],
        };

        let index_html_body = b"<html><body><h1>Hello World!</h1></body></html>".to_vec();
        let index_html_response = HttpResponse {
            status_code: 400,
            body: index_html_body,
            headers: vec![("IC-CertificateExpression".into(), cel_expr.to_string())],
            upgrade: None,
        };

        let certification =
            HttpCertification::full(&cel_expr, &index_html_request, &index_html_response, None)
                .unwrap();
        let index_html_entry =
            HttpCertificationTreeEntry::new(HttpCertificationPath::wildcard("/"), certification);
        tree.insert(&index_html_entry);

        let witness = tree.witness(&index_html_entry, "/").unwrap();

        let mut path = index_html_entry.to_tree_path();
        path.insert(0, b"http_expr".to_vec());

        assert!(matches!(
            witness.lookup_subtree(&path),
            SubtreeLookupResult::Found(_)
        ));
    }

    fn lookup_path_from_entry(entry: &HttpCertificationTreeEntry) -> Vec<Vec<u8>> {
        let mut lookup_path = entry.to_tree_path();
        lookup_path.insert(0, b"http_expr".to_vec());
        lookup_path
    }
}
