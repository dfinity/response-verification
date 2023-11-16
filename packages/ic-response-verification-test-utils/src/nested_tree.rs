use ic_certification::{AsHashTree, Hash, HashTree, RbTree};

pub trait NestedTreeKeyRequirements: Clone + AsRef<[u8]> + 'static {}
pub trait NestedTreeValueRequirements: AsHashTree + 'static {}
impl<T> NestedTreeKeyRequirements for T where T: Clone + AsRef<[u8]> + 'static {}
impl<T> NestedTreeValueRequirements for T where T: AsHashTree + 'static {}

#[derive(Debug, Clone)]
pub enum NestedTree<K: NestedTreeKeyRequirements, V: NestedTreeValueRequirements> {
    Leaf(V),
    Nested(RbTree<K, NestedTree<K, V>>),
}

impl<K: NestedTreeKeyRequirements, V: NestedTreeValueRequirements> Default for NestedTree<K, V> {
    fn default() -> Self {
        NestedTree::Nested(RbTree::<K, NestedTree<K, V>>::new())
    }
}

impl<K: NestedTreeKeyRequirements, V: NestedTreeValueRequirements> AsHashTree for NestedTree<K, V> {
    fn root_hash(&self) -> Hash {
        match self {
            NestedTree::Leaf(a) => a.root_hash(),
            NestedTree::Nested(tree) => tree.root_hash(),
        }
    }

    fn as_hash_tree(&self) -> HashTree {
        match self {
            NestedTree::Leaf(a) => a.as_hash_tree(),
            NestedTree::Nested(tree) => tree.as_hash_tree(),
        }
    }
}

impl<K: NestedTreeKeyRequirements, V: NestedTreeValueRequirements> NestedTree<K, V> {
    pub fn new() -> Self {
        NestedTree::Nested(RbTree::new())
    }

    pub fn insert(&mut self, path: &[K], value: V) {
        if let Some(key) = path.get(0) {
            match self {
                NestedTree::Leaf(_) => {
                    *self = NestedTree::new();
                    self.insert(path, value)
                }
                NestedTree::Nested(tree) => {
                    if tree.get(key.as_ref()).is_some() {
                        tree.modify(key.as_ref(), |child| child.insert(&path[1..], value))
                    } else {
                        tree.insert(key.clone(), NestedTree::new());
                        self.insert(path, value)
                    }
                }
            }
        } else {
            *self = NestedTree::Leaf(value);
        }
    }

    pub fn witness(&self, path: &[K]) -> HashTree {
        if let Some(key) = path.get(0) {
            match self {
                NestedTree::Leaf(value) => value.as_hash_tree(),
                NestedTree::Nested(tree) => {
                    tree.nested_witness(key.as_ref(), |tree| tree.witness(&path[1..]))
                }
            }
        } else {
            self.as_hash_tree()
        }
    }
}
