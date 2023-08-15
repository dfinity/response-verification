use crate::error::{CertificationTestError, CertificationTestResult};
use ic_crypto_tree_hash::{
    HashTreeBuilder, HashTreeBuilderImpl, LabeledTree, MixedHashTree, WitnessGenerator,
};

pub(crate) fn get_mixed_hash_tree(
    tree: &LabeledTree<Vec<u8>>,
) -> CertificationTestResult<MixedHashTree> {
    let mut hash_tree_builder = HashTreeBuilderImpl::new();
    hash_full_tree(&mut hash_tree_builder, tree);

    let witness_gen = hash_tree_builder
        .witness_generator()
        .ok_or(CertificationTestError::WitnessGenerationFailed)?;

    let mixed_hash_tree = witness_gen
        .mixed_hash_tree(tree)
        .map_err(|_| CertificationTestError::WitnessMergingFailed)?;

    Ok(mixed_hash_tree)
}

fn hash_full_tree(hash_tree_builder: &mut HashTreeBuilderImpl, tree: &LabeledTree<Vec<u8>>) {
    match tree {
        LabeledTree::Leaf(bytes) => {
            hash_tree_builder.start_leaf();
            hash_tree_builder.write_leaf(&bytes[..]);
            hash_tree_builder.finish_leaf();
        }
        LabeledTree::SubTree(map) => {
            hash_tree_builder.start_subtree();
            for (l, child) in map.iter() {
                hash_tree_builder.new_edge(l.clone());
                hash_full_tree(hash_tree_builder, child);
            }
            hash_tree_builder.finish_subtree();
        }
    }
}
