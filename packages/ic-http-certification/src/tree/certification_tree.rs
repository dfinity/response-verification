use super::{
    certification_tree_entry::HttpCertificationTreeEntry,
    certification_tree_path::{CertificationTreePathSegment, PATH_PREFIX_BYTES},
};
use crate::{
    tree::{HttpCertificationPathType, WILDCARD_PATH_TERMINATOR_BYTES},
    HttpCertificationPath,
};
use ic_certification::{
    empty, labeled, labeled_hash, merge_hash_trees, AsHashTree, HashTree, NestedTree,
};
use ic_representation_independent_hash::Sha256Digest;

type CertificationTree = NestedTree<CertificationTreePathSegment, Vec<u8>>;

/// A certification tree for generic HTTP requests.
#[derive(Debug)]
pub struct HttpCertificationTree {
    tree: CertificationTree,
}

impl Default for HttpCertificationTree {
    fn default() -> Self {
        Self::new(CertificationTree::default())
    }
}

impl HttpCertificationTree {
    /// Creates a new empty [HttpCertificationTree] from a given [CertificationTree].
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
    pub fn witness(&self, entry: &HttpCertificationTreeEntry, request_url: &str) -> HashTree {
        let witness = match entry.path.get_type() {
            HttpCertificationPathType::Exact(_) => self.tree.witness(&entry.to_tree_path()),

            HttpCertificationPathType::Wildcard(_) => {
                let requested_tree_path = HttpCertificationPath::exact(request_url).to_tree_path();

                // For wildcards we need to prove that there is not a more specific wildcard in the tree that
                // matches the request URL. So we step through the path and generate a witness for each subpath,
                // with and without trailing slashes.
                (0..requested_tree_path.len())
                    .flat_map(|index| {
                        let sub_path = requested_tree_path[0..index].to_vec();

                        let without_trailing_slash = [
                            sub_path.clone(),
                            vec![WILDCARD_PATH_TERMINATOR_BYTES.to_vec()],
                        ]
                        .concat();
                        let with_trailing_slash = [
                            sub_path,
                            vec![b"".to_vec(), WILDCARD_PATH_TERMINATOR_BYTES.to_vec()],
                        ]
                        .concat();

                        [without_trailing_slash, with_trailing_slash]
                    })
                    .fold(empty(), |acc, path| {
                        merge_hash_trees(acc, self.tree.witness(&path))
                    })
            }
        };

        labeled(PATH_PREFIX_BYTES, witness)
    }
}
