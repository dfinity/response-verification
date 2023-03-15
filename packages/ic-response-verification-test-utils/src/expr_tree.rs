use crate::{serialize_to_cbor, NestedTree};
use ic_certified_map::{labeled, labeled_hash, AsHashTree, Hash, HashTree};
use ic_crypto_tree_hash::Digest;

const LABEL_EXPR: &[u8] = b"http_expr";

#[derive(Debug, Clone)]
pub enum ExprTreeKey {
    String(String),
    Bytes(Vec<u8>),
}

impl AsRef<[u8]> for ExprTreeKey {
    fn as_ref(&self) -> &[u8] {
        match self {
            ExprTreeKey::String(s) => s.as_bytes(),
            ExprTreeKey::Bytes(b) => b.as_slice(),
        }
    }
}

impl From<&str> for ExprTreeKey {
    fn from(s: &str) -> Self {
        Self::String(s.into())
    }
}

impl From<&[u8]> for ExprTreeKey {
    fn from(slice: &[u8]) -> Self {
        Self::Bytes(slice.to_vec())
    }
}

impl From<String> for ExprTreeKey {
    fn from(s: String) -> Self {
        Self::String(s)
    }
}

#[derive(Debug, Clone)]
pub struct ExprTree {
    tree: NestedTree<ExprTreeKey, Vec<u8>>,
}

impl Default for ExprTree {
    fn default() -> Self {
        Self::new()
    }
}

impl ExprTree {
    pub fn new() -> Self {
        Self {
            tree: NestedTree::new(),
        }
    }

    pub fn insert(&mut self, path: &[ExprTreeKey]) {
        self.tree.insert(path, b"".to_vec())
    }

    pub fn serialize_to_cbor(&self, path: &[ExprTreeKey]) -> Vec<u8> {
        let tree = self.tree.witness(path);
        let labeled_tree = labeled(LABEL_EXPR, tree);

        serialize_to_cbor::<HashTree>(&labeled_tree)
    }

    pub fn get_certified_data(&self) -> Digest {
        let root_hash = self.tree.root_hash();
        let labeled_tree = labeled_hash(LABEL_EXPR, &root_hash);

        Digest(labeled_tree)
    }
}

pub fn create_expr_tree_path(
    expr_path: &[&str],
    expr_hash: &Hash,
    req_hash: Option<&Hash>,
    res_hash: Option<&Hash>,
) -> Vec<ExprTreeKey> {
    let mut path: Vec<ExprTreeKey> = vec![];
    path.extend(expr_path.iter().map(|e| ExprTreeKey::from(*e)));

    path.push(expr_hash.as_slice().into());
    if let Some(req_hash) = req_hash {
        path.push(req_hash.as_slice().into());
    } else {
        path.push("".into());
    }

    if let Some(res_hash) = res_hash {
        path.push(res_hash.as_slice().into());
    }

    path
}
