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
    let canister_ranges = serialize_to_cbor(&canister_ranges.to_vec());

    Ok(LabeledTree::SubTree(flatmap![
        Label::from("subnet") => LabeledTree::SubTree(flatmap![
            Label::from(subnet_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                Label::from("canister_ranges") => LabeledTree::Leaf(canister_ranges),
                Label::from("public_key") => LabeledTree::Leaf(delegatee_public_key.to_vec()),
            ])
        ]),
        Label::from("time") => LabeledTree::Leaf(encoded_time.to_vec())
    ]))
}
