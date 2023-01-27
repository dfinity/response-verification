use crate::cbor::{parse_cbor, CborHashTree, CborValue};
use crate::error::ResponseVerificationError;
use ic_certification::{
    hash_tree::{empty, fork, label, leaf, pruned, Label, Sha256Digest},
    HashTree,
};

pub trait HashTreeToCbor<'a> {
    fn from_cbor(cbor: &[u8]) -> Result<HashTree<'a>, ResponseVerificationError>;
}

impl<'a> HashTreeToCbor<'a> for HashTree<'a> {
    fn from_cbor(cbor: &[u8]) -> Result<HashTree<'a>, ResponseVerificationError> {
        let parsed_cbor = parse_cbor(cbor)
            .map_err(|e| ResponseVerificationError::MalformedCbor(e.to_string()))?;

        parsed_cbor_to_tree(&parsed_cbor)
    }
}

pub fn parsed_cbor_to_tree<'a>(
    parsed_cbor: &CborValue,
) -> Result<HashTree<'a>, ResponseVerificationError> {
    if let CborValue::Array(mut cbor_tags) = parsed_cbor.to_owned() {
        cbor_tags.reverse();

        if let Some(CborValue::HashTree(hash_tree_tag)) = cbor_tags.pop() {
            return match hash_tree_tag {
                CborHashTree::Empty => Ok(empty()),

                CborHashTree::Leaf => {
                    return if let Some(CborValue::ByteString(data)) = cbor_tags.pop() {
                        Ok(leaf(data))
                    } else {
                        Err(ResponseVerificationError::MalformedHashTree(String::from(
                            "Missing ByteString for Leaf node",
                        )))
                    };
                }

                CborHashTree::Pruned => {
                    return if let Some(CborValue::ByteString(data)) = cbor_tags.pop() {
                        let digest: Sha256Digest = TryFrom::<&[u8]>::try_from(data.as_ref())
                            .map_err(ResponseVerificationError::IncorrectPrunedDataLength)?;

                        Ok(pruned(digest))
                    } else {
                        Err(ResponseVerificationError::MalformedHashTree(String::from(
                            "Missing ByteString for Pruned node",
                        )))
                    };
                }

                CborHashTree::Labelled => {
                    return if let (Some(CborValue::ByteString(data)), Some(child_tag)) =
                        (cbor_tags.pop(), cbor_tags.pop())
                    {
                        let node_label = Label::from(data);
                        let child_node = parsed_cbor_to_tree(&child_tag)?;

                        Ok(label(node_label, child_node))
                    } else {
                        Err(ResponseVerificationError::MalformedHashTree(String::from(
                            "Missing ByteString or child node for Labelled node",
                        )))
                    };
                }

                CborHashTree::Fork => {
                    return if let (Some(left_tag), Some(right_tag)) =
                        (cbor_tags.pop(), cbor_tags.pop())
                    {
                        let left = parsed_cbor_to_tree(&left_tag)?;
                        let right = parsed_cbor_to_tree(&right_tag)?;

                        Ok(fork(left, right))
                    } else {
                        Err(ResponseVerificationError::MalformedHashTree(String::from(
                            "Missing child nodes for Fork node",
                        )))
                    };
                }
            };
        } else {
            Err(ResponseVerificationError::MalformedHashTree(String::from(
                "Expected Hash Tree cbor tag",
            )))
        }
    } else {
        Err(ResponseVerificationError::MalformedHashTree(String::from(
            "Expected Array cbor tag",
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_certification::hash_tree::{
        empty, fork, label, leaf, pruned, pruned_from_hex, Label, LookupResult,
    };

    fn lookup_path<'a, P: AsRef<[&'static str]>>(
        tree: &'a HashTree<'a>,
        path: P,
    ) -> LookupResult<'a> {
        let path: Vec<Label> = path.as_ref().iter().map(|l| l.into()).collect();

        tree.lookup_path(&path)
    }

    #[test]
    fn works_with_simple_tree() {
        let original_tree = fork(
            label("label 1", empty()),
            fork(
                pruned(*b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"),
                leaf(&[1u8, 2, 3, 4, 5, 6]),
            ),
        );
        let tree_cbor = serde_cbor::to_vec(&original_tree).expect("Failed to encode tree to cbor");

        let tree = HashTree::from_cbor(&tree_cbor).expect("Failed to deserialize tree");

        assert_eq!(
            hex::encode(tree.digest()),
            "69cf325d0f20505b261821a7e77ff72fb9a8753a7964f0b587553bfb44e72532"
        );
    }

    #[test]
    fn spec_example() {
        // This is the example straight from the spec.
        let original_tree = fork(
            fork(
                label(
                    "a",
                    fork(
                        fork(label("x", leaf(b"hello")), empty()),
                        label("y", leaf(b"world")),
                    ),
                ),
                label("b", leaf(b"good")),
            ),
            fork(label("c", empty()), label("d", leaf(b"morning"))),
        );
        let tree_cbor = serde_cbor::to_vec(&original_tree).expect("Failed to encode tree to cbor");
        let tree = HashTree::from_cbor(&tree_cbor).expect("Failed to deserialize tree");

        assert_eq!(
            hex::encode(tree.digest()),
            "eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0"
        );
    }

    #[test]
    fn spec_example_pruned() {
        // This is the example straight from the spec.
        let original_tree = fork(
            fork(
                label(
                    "a",
                    fork(
                        pruned_from_hex(
                            "1b4feff9bef8131788b0c9dc6dbad6e81e524249c879e9f10f71ce3749f5a638",
                        )
                        .unwrap(),
                        label("y", leaf(b"world")),
                    ),
                ),
                label(
                    "b",
                    pruned_from_hex(
                        "7b32ac0c6ba8ce35ac82c255fc7906f7fc130dab2a090f80fe12f9c2cae83ba6",
                    )
                    .unwrap(),
                ),
            ),
            fork(
                pruned_from_hex("ec8324b8a1f1ac16bd2e806edba78006479c9877fed4eb464a25485465af601d")
                    .unwrap(),
                label("d", leaf(b"morning")),
            ),
        );
        let tree_cbor = serde_cbor::to_vec(&original_tree).expect("Failed to encode tree to cbor");
        let tree = HashTree::from_cbor(&tree_cbor).expect("Failed to deserialize tree");

        assert_eq!(
            hex::encode(tree.digest()),
            "eb5c5b2195e62d996b84c9bcc8259d19a83786a2f59e0878cec84c811f669aa0"
        );

        assert_eq!(lookup_path(&tree, ["a", "a"]), LookupResult::Unknown);
        assert_eq!(
            lookup_path(&tree, ["a", "y"]),
            LookupResult::Found(b"world")
        );
        assert_eq!(lookup_path(&tree, ["aa"]), LookupResult::Absent);
        assert_eq!(lookup_path(&tree, ["ax"]), LookupResult::Absent);
        assert_eq!(lookup_path(&tree, ["b"]), LookupResult::Unknown);
        assert_eq!(lookup_path(&tree, ["bb"]), LookupResult::Unknown);
        assert_eq!(lookup_path(&tree, ["d"]), LookupResult::Found(b"morning"));
        assert_eq!(lookup_path(&tree, ["e"]), LookupResult::Absent);
    }

    #[test]
    fn can_lookup_paths_1() {
        let original_tree = fork(
            label("label 1", empty()),
            fork(
                pruned([1; 32]),
                fork(
                    label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                    label("label 5", empty()),
                ),
            ),
        );
        let tree_cbor = serde_cbor::to_vec(&original_tree).expect("Failed to encode tree to cbor");
        let tree = HashTree::from_cbor(&tree_cbor).expect("Failed to deserialize tree");

        assert_eq!(tree.lookup_path(&["label 0".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 1".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Unknown);
        assert_eq!(
            tree.lookup_path(&["label 3".into()]),
            LookupResult::Found(&[1, 2, 3, 4, 5, 6])
        );
        assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Absent);
    }

    #[test]
    fn can_lookup_paths_2() {
        let original_tree = fork(
            label("label 1", empty()),
            fork(
                fork(
                    label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                    label("label 5", empty()),
                ),
                pruned([1; 32]),
            ),
        );
        let tree_cbor = serde_cbor::to_vec(&original_tree).expect("Failed to encode tree to cbor");
        let tree = HashTree::from_cbor(&tree_cbor).expect("Failed to deserialize tree");

        assert_eq!(tree.lookup_path(&["label 0".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 1".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Absent);
        assert_eq!(
            tree.lookup_path(&["label 3".into()]),
            LookupResult::Found(&[1, 2, 3, 4, 5, 6])
        );
        assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Unknown);
    }

    #[test]
    fn can_lookup_paths_3() {
        let original_tree = fork(
            pruned([0; 32]),
            fork(
                pruned([1; 32]),
                fork(
                    label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                    label("label 5", empty()),
                ),
            ),
        );
        let tree_cbor = serde_cbor::to_vec(&original_tree).expect("Failed to encode tree to cbor");
        let tree = HashTree::from_cbor(&tree_cbor).expect("Failed to deserialize tree");

        assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Unknown);
        assert_eq!(
            tree.lookup_path(&["label 3".into()]),
            LookupResult::Found(&[1, 2, 3, 4, 5, 6])
        );
        assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Absent);
    }

    #[test]
    fn can_lookup_paths_4() {
        let original_tree = fork(
            pruned([0; 32]),
            fork(
                fork(
                    label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                    label("label 5", empty()),
                ),
                pruned([1; 32]),
            ),
        );
        let tree_cbor = serde_cbor::to_vec(&original_tree).expect("Failed to encode tree to cbor");
        let tree = HashTree::from_cbor(&tree_cbor).expect("Failed to deserialize tree");

        assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Unknown);
        assert_eq!(
            tree.lookup_path(&["label 3".into()]),
            LookupResult::Found(&[1, 2, 3, 4, 5, 6])
        );
        assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Unknown);
    }

    #[test]
    fn can_lookup_paths_5() {
        let original_tree = fork(
            fork(
                pruned([1; 32]),
                fork(
                    label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                    label("label 5", empty()),
                ),
            ),
            label("label 7", empty()),
        );
        let tree_cbor = serde_cbor::to_vec(&original_tree).expect("Failed to encode tree to cbor");
        let tree = HashTree::from_cbor(&tree_cbor).expect("Failed to deserialize tree");

        assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Unknown);
        assert_eq!(
            tree.lookup_path(&["label 3".into()]),
            LookupResult::Found(&[1, 2, 3, 4, 5, 6])
        );
        assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 7".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 8".into()]), LookupResult::Absent);
    }

    #[test]
    fn can_lookup_paths_6() {
        let original_tree = fork(
            fork(
                fork(
                    label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                    label("label 5", empty()),
                ),
                pruned([1; 32]),
            ),
            label("label 7", empty()),
        );
        let tree_cbor = serde_cbor::to_vec(&original_tree).expect("Failed to encode tree to cbor");
        let tree = HashTree::from_cbor(&tree_cbor).expect("Failed to deserialize tree");

        assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Absent);
        assert_eq!(
            tree.lookup_path(&["label 3".into()]),
            LookupResult::Found(&[1, 2, 3, 4, 5, 6])
        );
        assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Unknown);
        assert_eq!(tree.lookup_path(&["label 7".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 8".into()]), LookupResult::Absent);
    }

    #[test]
    fn can_lookup_paths_7() {
        let original_tree = fork(
            fork(
                pruned([1; 32]),
                fork(
                    label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                    label("label 5", empty()),
                ),
            ),
            pruned([0; 32]),
        );
        let tree_cbor = serde_cbor::to_vec(&original_tree).expect("Failed to encode tree to cbor");
        let tree = HashTree::from_cbor(&tree_cbor).expect("Failed to deserialize tree");

        assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Unknown);
        assert_eq!(
            tree.lookup_path(&["label 3".into()]),
            LookupResult::Found(&[1, 2, 3, 4, 5, 6])
        );
        assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Unknown);
    }

    #[test]
    fn can_lookup_paths_8() {
        let original_tree = fork(
            fork(
                fork(
                    label("label 3", leaf(vec![1, 2, 3, 4, 5, 6])),
                    label("label 5", empty()),
                ),
                pruned([1; 32]),
            ),
            pruned([0; 32]),
        );
        let tree_cbor = serde_cbor::to_vec(&original_tree).expect("Failed to encode tree to cbor");
        let tree = HashTree::from_cbor(&tree_cbor).expect("Failed to deserialize tree");

        assert_eq!(tree.lookup_path(&["label 2".into()]), LookupResult::Absent);
        assert_eq!(
            tree.lookup_path(&["label 3".into()]),
            LookupResult::Found(&[1, 2, 3, 4, 5, 6])
        );
        assert_eq!(tree.lookup_path(&["label 4".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 5".into()]), LookupResult::Absent);
        assert_eq!(tree.lookup_path(&["label 6".into()]), LookupResult::Unknown);
    }
}
