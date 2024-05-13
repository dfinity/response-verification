use crate::{empty, fork, labeled, leaf, pruned, AsHashTree, Hash, HashTree, HashTreeNode, RbTree};
use std::fmt::Debug;

pub trait NestedTreeKeyRequirements: Debug + Clone + AsRef<[u8]> + 'static {}
pub trait NestedTreeValueRequirements: Debug + Clone + AsHashTree + 'static {}
impl<T> NestedTreeKeyRequirements for T where T: Debug + Clone + AsRef<[u8]> + 'static {}
impl<T> NestedTreeValueRequirements for T where T: Debug + Clone + AsHashTree + 'static {}

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
    pub fn get(&self, path: &[K]) -> Option<&V> {
        if let Some(key) = path.first() {
            match self {
                NestedTree::Leaf(_) => None,
                NestedTree::Nested(tree) => tree
                    .get(key.as_ref())
                    .and_then(|child| child.get(&path[1..])),
            }
        } else {
            match self {
                NestedTree::Leaf(value) => Some(value),
                NestedTree::Nested(_) => None,
            }
        }
    }

    /// Returns true if there is a leaf at the specified path
    pub fn contains_leaf(&self, path: &[K]) -> bool {
        if let Some(key) = path.first() {
            match self {
                NestedTree::Leaf(_) => false,
                NestedTree::Nested(tree) => tree
                    .get(key.as_ref())
                    .map(|child| child.contains_leaf(&path[1..]))
                    .unwrap_or(false),
            }
        } else {
            matches!(self, NestedTree::Leaf(_))
        }
    }

    /// Returns true if there is a leaf or a subtree at the specified path
    pub fn contains_path(&self, path: &[K]) -> bool {
        if let Some(key) = path.first() {
            match self {
                NestedTree::Leaf(_) => false,
                NestedTree::Nested(tree) => tree
                    .get(key.as_ref())
                    .map(|child| child.contains_path(&path[1..]))
                    .unwrap_or(false),
            }
        } else {
            true
        }
    }

    pub fn insert(&mut self, path: &[K], value: V) {
        if let Some(key) = path.first() {
            match self {
                NestedTree::Leaf(_) => {
                    *self = NestedTree::default();
                    self.insert(path, value);
                }
                NestedTree::Nested(tree) => {
                    if tree.get(key.as_ref()).is_some() {
                        tree.modify(key.as_ref(), |child| child.insert(&path[1..], value));
                    } else {
                        tree.insert(key.clone(), NestedTree::default());
                        self.insert(path, value);
                    }
                }
            }
        } else {
            *self = NestedTree::Leaf(value);
        }
    }

    pub fn delete(&mut self, path: &[K]) {
        if let Some(key) = path.first() {
            match self {
                NestedTree::Leaf(_) => {}
                NestedTree::Nested(tree) => {
                    tree.modify(key.as_ref(), |child| child.delete(&path[1..]));

                    // after deleting the subtree located at `path[1..]`,
                    // check if the subtree located at `path[0]` is empty,
                    // if it is, remove it
                    if let Some(root) = tree.get(key.as_ref()) {
                        match root {
                            NestedTree::Leaf(_) => {}
                            NestedTree::Nested(nested_tree) => {
                                if nested_tree.is_empty() {
                                    tree.delete(key.as_ref());
                                }
                            }
                        }
                    }
                }
            }
        } else {
            *self = NestedTree::default();
        }
    }

    pub fn witness(&self, path: &[K]) -> HashTree {
        if let Some(key) = path.first() {
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

pub fn merge_hash_trees(lhs: HashTree, rhs: HashTree) -> HashTree {
    match (lhs.root, rhs.root) {
        (HashTreeNode::Pruned(l), HashTreeNode::Pruned(r)) => {
            if l != r {
                panic!("merge_hash_trees: inconsistent hashes");
            }
            pruned(l)
        }
        (HashTreeNode::Pruned(_), r) => HashTree { root: r },
        (l, HashTreeNode::Pruned(_)) => HashTree { root: l },
        (HashTreeNode::Fork(l), HashTreeNode::Fork(r)) => fork(
            merge_hash_trees(HashTree { root: l.0 }, HashTree { root: r.0 }),
            merge_hash_trees(HashTree { root: l.1 }, HashTree { root: r.1 }),
        ),
        (HashTreeNode::Labeled(l_label, l), HashTreeNode::Labeled(r_label, r)) => {
            if l_label != r_label {
                panic!("merge_hash_trees: inconsistent hash tree labels");
            }
            labeled(
                l_label,
                merge_hash_trees(HashTree { root: *l }, HashTree { root: *r }),
            )
        }
        (HashTreeNode::Empty(), HashTreeNode::Empty()) => empty(),
        (HashTreeNode::Empty(), r) => HashTree { root: r },
        (l, HashTreeNode::Empty()) => HashTree { root: l },
        (HashTreeNode::Leaf(l), HashTreeNode::Leaf(r)) => {
            if l != r {
                panic!("merge_hash_trees: inconsistent leaves");
            }
            leaf(l)
        }
        (_l, _r) => {
            panic!("merge_hash_trees: inconsistent tree structure");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LookupResult;
    use rstest::*;

    #[rstest]
    fn nested_tree_operation() {
        let mut tree: NestedTree<&str, Vec<u8>> = NestedTree::default();
        // insertion
        tree.insert(&["one", "two"], vec![2]);
        tree.insert(&["one", "three"], vec![3]);

        assert_eq!(tree.get(&["one", "two"]), Some(&vec![2]));
        assert_eq!(tree.get(&["one", "three"]), Some(&vec![3]));
        assert_eq!(tree.get(&["one", "two", "three"]), None);
        assert_eq!(tree.get(&["one", "three", "two"]), None);
        assert_eq!(tree.get(&["one"]), None);

        assert!(tree.contains_leaf(&["one", "two"]));
        assert!(tree.contains_leaf(&["one", "three"]));
        assert!(!tree.contains_leaf(&["one", "two", "three"]));
        assert!(!tree.contains_leaf(&["one", "three", "two"]));
        assert!(!tree.contains_leaf(&["one"]));

        assert!(tree.contains_path(&["one", "two"]));
        assert!(tree.contains_path(&["one", "three"]));
        assert!(!tree.contains_path(&["one", "two", "three"]));
        assert!(!tree.contains_path(&["one", "three", "two"]));
        assert!(tree.contains_path(&["one"]));

        // deleting non-existent key doesn't do anything
        tree.delete(&["one", "two", "three"]);

        assert_eq!(tree.get(&["one", "two"]), Some(&vec![2]));
        assert_eq!(tree.get(&["one", "three"]), Some(&vec![3]));
        assert_eq!(tree.get(&["one", "two", "three"]), None);
        assert_eq!(tree.get(&["one", "three", "two"]), None);
        assert_eq!(tree.get(&["one"]), None);

        assert!(tree.contains_leaf(&["one", "two"]));
        assert!(tree.contains_leaf(&["one", "three"]));
        assert!(!tree.contains_leaf(&["one", "two", "three"]));
        assert!(!tree.contains_leaf(&["one", "three", "two"]));
        assert!(!tree.contains_leaf(&["one"]));

        assert!(tree.contains_path(&["one", "two"]));
        assert!(tree.contains_path(&["one", "three"]));
        assert!(!tree.contains_path(&["one", "two", "three"]));
        assert!(!tree.contains_path(&["one", "three", "two"]));
        assert!(tree.contains_path(&["one"]));

        // deleting existing key works
        tree.delete(&["one", "three"]);

        assert_eq!(tree.get(&["one", "two"]), Some(&vec![2]));
        assert_eq!(tree.get(&["one", "three"]), None);
        assert_eq!(tree.get(&["one", "two", "three"]), None);
        assert_eq!(tree.get(&["one", "three", "two"]), None);
        assert_eq!(tree.get(&["one"]), None);

        assert!(tree.contains_leaf(&["one", "two"]));
        assert!(!tree.contains_leaf(&["one", "three"]));
        assert!(!tree.contains_leaf(&["one", "two", "three"]));
        assert!(!tree.contains_leaf(&["one", "three", "two"]));
        assert!(!tree.contains_leaf(&["one"]));

        assert!(tree.contains_path(&["one", "two"]));
        assert!(!tree.contains_path(&["one", "three"]));
        assert!(!tree.contains_path(&["one", "two", "three"]));
        assert!(!tree.contains_path(&["one", "three", "two"]));
        assert!(tree.contains_path(&["one"]));

        // deleting subtree works
        tree.delete(&["one"]);

        assert_eq!(tree.get(&["one", "two"]), None);
        assert_eq!(tree.get(&["one", "three"]), None);
        assert_eq!(tree.get(&["one", "two", "three"]), None);
        assert_eq!(tree.get(&["one", "three", "two"]), None);
        assert_eq!(tree.get(&["one"]), None);

        assert!(!tree.contains_leaf(&["one", "two"]));
        assert!(!tree.contains_leaf(&["one", "three"]));
        assert!(!tree.contains_leaf(&["one", "two", "three"]));
        assert!(!tree.contains_leaf(&["one", "three", "two"]));
        assert!(!tree.contains_leaf(&["one"]));

        assert!(!tree.contains_path(&["one", "two"]));
        assert!(!tree.contains_path(&["one", "three"]));
        assert!(!tree.contains_path(&["one", "two", "three"]));
        assert!(!tree.contains_path(&["one", "three", "two"]));
        assert!(!tree.contains_path(&["one"]));
    }

    #[rstest]
    fn delete_removes_empty_subpaths() {
        let mut tree: NestedTree<&str, Vec<u8>> = NestedTree::default();

        tree.insert(&["one", "two", "three", "four"], vec![4]);
        tree.insert(&["one", "two", "three", "five"], vec![5]);
        tree.insert(&["one", "two", "six"], vec![6]);
        tree.insert(&["one", "seven"], vec![7]);

        assert!(tree.contains_leaf(&["one", "two", "three", "four"]));
        assert!(tree.contains_leaf(&["one", "two", "three", "five"]));
        assert!(tree.contains_leaf(&["one", "two", "six"]));
        assert!(tree.contains_leaf(&["one", "seven"]));

        assert!(tree.contains_path(&["one", "two", "three", "four"]));
        assert!(tree.contains_path(&["one", "two", "three", "five"]));
        assert!(tree.contains_path(&["one", "two", "three"]));
        assert!(tree.contains_path(&["one", "two", "six"]));
        assert!(tree.contains_path(&["one", "two"]));
        assert!(tree.contains_path(&["one", "seven"]));
        assert!(tree.contains_path(&["one"]));

        tree.delete(&["one", "two", "three", "four"]);

        assert!(!tree.contains_leaf(&["one", "two", "three", "four"]));
        assert!(tree.contains_leaf(&["one", "two", "three", "five"]));
        assert!(tree.contains_leaf(&["one", "two", "six"]));
        assert!(tree.contains_leaf(&["one", "seven"]));

        assert!(!tree.contains_path(&["one", "two", "three", "four"]));
        assert!(tree.contains_path(&["one", "two", "three", "five"]));
        assert!(tree.contains_path(&["one", "two", "three"]));
        assert!(tree.contains_path(&["one", "two", "six"]));
        assert!(tree.contains_path(&["one", "two"]));
        assert!(tree.contains_path(&["one", "seven"]));
        assert!(tree.contains_path(&["one"]));

        tree.delete(&["one", "two", "three", "five"]);

        assert!(!tree.contains_leaf(&["one", "two", "three", "four"]));
        assert!(!tree.contains_leaf(&["one", "two", "three", "five"]));
        assert!(tree.contains_leaf(&["one", "two", "six"]));
        assert!(tree.contains_leaf(&["one", "seven"]));

        assert!(!tree.contains_path(&["one", "two", "three", "four"]));
        assert!(!tree.contains_path(&["one", "two", "three", "five"]));
        assert!(!tree.contains_path(&["one", "two", "three"]));
        assert!(tree.contains_path(&["one", "two", "six"]));
        assert!(tree.contains_path(&["one", "two"]));
        assert!(tree.contains_path(&["one", "seven"]));
        assert!(tree.contains_path(&["one"]));

        tree.delete(&["one", "two", "six"]);

        assert!(!tree.contains_leaf(&["one", "two", "three", "four"]));
        assert!(!tree.contains_leaf(&["one", "two", "three", "five"]));
        assert!(!tree.contains_leaf(&["one", "two", "six"]));
        assert!(tree.contains_leaf(&["one", "seven"]));

        assert!(!tree.contains_path(&["one", "two", "three", "four"]));
        assert!(!tree.contains_path(&["one", "two", "three", "five"]));
        assert!(!tree.contains_path(&["one", "two", "three"]));
        assert!(!tree.contains_path(&["one", "two", "six"]));
        assert!(!tree.contains_path(&["one", "two"]));
        assert!(tree.contains_path(&["one", "seven"]));
        assert!(tree.contains_path(&["one"]));

        tree.delete(&["one", "seven"]);

        assert!(!tree.contains_leaf(&["one", "two", "three", "four"]));
        assert!(!tree.contains_leaf(&["one", "two", "three", "five"]));
        assert!(!tree.contains_leaf(&["one", "two", "six"]));
        assert!(!tree.contains_leaf(&["one", "seven"]));

        assert!(!tree.contains_path(&["one", "two", "three", "four"]));
        assert!(!tree.contains_path(&["one", "two", "three", "five"]));
        assert!(!tree.contains_path(&["one", "two", "three"]));
        assert!(!tree.contains_path(&["one", "two", "six"]));
        assert!(!tree.contains_path(&["one", "two"]));
        assert!(!tree.contains_path(&["one", "seven"]));
        assert!(!tree.contains_path(&["one"]));
    }

    #[rstest]
    fn merge_hash_trees_merge_witness() {
        let mut tree: NestedTree<&str, Vec<u8>> = NestedTree::default();
        tree.insert(&["one", "two"], vec![1]);
        tree.insert(&["one", "three"], vec![2]);
        tree.insert(&["two", "two"], vec![3]);
        tree.insert(&["two", "three"], vec![4]);

        let witness_one_two = tree.witness(&["one", "two"]);
        let witness_one_three = tree.witness(&["two", "three"]);
        let witness_merged = merge_hash_trees(witness_one_two, witness_one_three);

        assert!(matches!(
            witness_merged.lookup_path(&["one", "two"]),
            LookupResult::Found(val) if val == vec![1]
        ));
        assert!(matches!(
            witness_merged.lookup_path(&["one", "three"]),
            LookupResult::Unknown
        ));
        assert!(matches!(
            witness_merged.lookup_path(&["two", "three"]),
            LookupResult::Found(val) if val == vec![4]
        ));
        assert!(matches!(
            witness_merged.lookup_path(&["two", "two"]),
            LookupResult::Unknown
        ));

        let witness_merged_left_empty = merge_hash_trees(empty(), witness_merged.clone());
        assert_eq!(witness_merged_left_empty, witness_merged);

        let witness_merged_right_empty = merge_hash_trees(witness_merged.clone(), empty());
        assert_eq!(witness_merged_right_empty, witness_merged);
    }

    #[rstest]
    // empty
    #[case::empty_labeled(empty(), labeled_a(), labeled_a())]
    #[case::labeled_empty(labeled_a(), empty(), labeled_a())]
    #[case::empty_leaf(empty(), leaf_a(), leaf_a())]
    #[case::leaf_empty(leaf_a(), empty(), leaf_a())]
    // pruned
    #[case::pruned_pruned(pruned_a(), pruned_a(), pruned_a())]
    #[case::pruned_labeled(pruned_a(), labeled_a(), labeled_a())]
    #[case::labeled_pruned(labeled_a(), pruned_a(), labeled_a())]
    #[case::pruned_leaf(pruned_a(), leaf_a(), leaf_a())]
    #[case::leaf_pruned(leaf_a(), pruned_a(), leaf_a())]
    #[case::empty_pruned(empty(), pruned_a(), empty())]
    #[case::pruned_empty(pruned_a(), empty(), empty())]
    // matching
    #[case::empty_empty(empty(), empty(), empty())]
    #[case::fork_fork(fork_a(), fork_a(), fork_a())]
    #[case::leaf_leaf(leaf_a(), leaf_a(), leaf_a())]
    // mismatched
    fn merge_hash_trees_operation(
        #[case] lhs: HashTree,
        #[case] rhs: HashTree,
        #[case] merged: HashTree,
    ) {
        assert_eq!(merge_hash_trees(lhs, rhs), merged);
    }

    #[rstest]
    #[should_panic]
    #[case::mismatched_pruned(pruned_a(), pruned_b())]
    #[should_panic]
    #[case::mismatched_labeled(labeled_a(), labeled_b())]
    #[should_panic]
    #[case::mismatched_leaves(leaf_a(), leaf_b())]
    #[should_panic]
    #[case::mismatched_leaf_and_fork(leaf_a(), fork_a())]
    #[should_panic]
    #[case::mismatched_fork_and_leaf(fork_a(), leaf_a())]
    #[should_panic]
    #[case::mismatched_label_and_fork(labeled_a(), fork_a())]
    #[should_panic]
    #[case::mismatched_fork_and_label(fork_a(), labeled_a())]
    #[should_panic]
    #[case::mismatched_leaf_and_fork(leaf_a(), fork_a())]
    #[should_panic]
    #[case::mismatched_fork_and_leaf(fork_a(), leaf_a())]
    fn merge_hash_trees_inconsistent_structure(#[case] lhs: HashTree, #[case] rhs: HashTree) {
        merge_hash_trees(lhs, rhs);
    }

    #[fixture]
    fn pruned_a() -> HashTree {
        pruned(Hash::from([0u8; 32]))
    }

    #[fixture]
    fn pruned_b() -> HashTree {
        pruned(Hash::from([1u8; 32]))
    }

    #[fixture]
    fn labeled_a() -> HashTree {
        labeled("foo", pruned_a())
    }

    #[fixture]
    fn labeled_b() -> HashTree {
        labeled("bar", pruned_a())
    }

    #[fixture]
    fn leaf_a() -> HashTree {
        leaf(Hash::from([0u8; 32]))
    }

    #[fixture]
    fn leaf_b() -> HashTree {
        leaf(Hash::from([1u8; 32]))
    }

    #[fixture]
    fn fork_a() -> HashTree {
        fork(leaf_a(), leaf(Hash::from([1u8; 32])))
    }
}
