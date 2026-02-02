use crate::{encoding::serialize_to_cbor, error::CertificationTestResult};
use ic_crypto_tree_hash::{flatmap, Label, LabeledTree};
use ic_types::{CanisterId, SubnetId};

pub(crate) fn create_certificate_tree(
    canister_id: &CanisterId,
    certified_data: &[u8],
    encoded_time: &[u8],
) -> LabeledTree<Vec<u8>> {
    LabeledTree::SubTree(flatmap![
        Label::from("canister") => LabeledTree::SubTree(flatmap![
            Label::from(canister_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                Label::from("certified_data") => LabeledTree::Leaf(certified_data.to_vec()),
            ])
        ]),
        Label::from("time") => LabeledTree::Leaf(encoded_time.to_vec())])
}

pub(crate) fn create_delegation_tree(
    delegatee_public_key: &[u8],
    encoded_time: &[u8],
    subnet_id: &SubnetId,
    canister_ranges: &[(CanisterId, CanisterId)],
) -> CertificationTestResult<LabeledTree<Vec<u8>>> {
    let canister_ranges_cbor = serialize_to_cbor(&canister_ranges.to_vec());

    // Use the actual dfx structure: /canister_ranges/<subnet_id>/<range_key>
    // The range_key is a placeholder - in real certificates it's derived from the canister range
    let range_key = vec![0xFF; 10]; // Placeholder range key
    
    Ok(LabeledTree::SubTree(flatmap![
        Label::from("canister_ranges") => LabeledTree::SubTree(flatmap![
            Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                Label::from(range_key) => LabeledTree::Leaf(canister_ranges_cbor),
            ]),
        ]),
        Label::from("subnet") => LabeledTree::SubTree(flatmap![
            Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                Label::from("public_key") => LabeledTree::Leaf(delegatee_public_key.to_vec()),
            ])
        ]),
        Label::from("time") => LabeledTree::Leaf(encoded_time.to_vec())
    ]))
}
