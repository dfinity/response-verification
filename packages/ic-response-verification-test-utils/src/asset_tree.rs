use crate::hash::hash;
use crate::{cbor_encode, hash_from_hex};
use ic_certification::{labeled, labeled_hash, AsHashTree, Hash, HashTree, RbTree};

const LABEL_ASSETS: &[u8] = b"http_assets";

pub struct AssetTree {
    tree: RbTree<&'static str, Hash>,
}

impl Default for AssetTree {
    fn default() -> Self {
        let mut asset_tree = Self::new();
        let body = "Hello World!";

        asset_tree.insert(Self::DEFAULT_PATH, body);

        asset_tree
    }
}

impl AssetTree {
    pub const DEFAULT_PATH: &'static str = "/";

    pub fn new() -> Self {
        Self {
            tree: RbTree::new(),
        }
    }

    pub fn insert(&mut self, path: &'static str, body: &str) {
        let body_hash = hash(body);

        self.tree.insert(path, body_hash);
    }

    pub fn serialize_to_cbor(&self, path: Option<&'static str>) -> Vec<u8> {
        let path = path.unwrap_or(Self::DEFAULT_PATH);
        let tree = self.tree.witness(path.as_bytes());
        let labeled_tree = labeled(LABEL_ASSETS, tree);

        cbor_encode::<HashTree>(&labeled_tree)
    }

    pub fn get_certified_data(&self) -> [u8; 32] {
        let root_hash = self.tree.root_hash();

        labeled_hash(LABEL_ASSETS, &root_hash)
    }
}

pub fn create_certified_data(data: &str) -> [u8; 32] {
    let hash = hash_from_hex(data);

    labeled_hash(LABEL_ASSETS, &hash)
}
