use ic_certification::{Certificate, HashTree, LookupResult};

pub fn validate_tree(canister_id: &[u8], certificate: &Certificate, tree: &HashTree) -> bool {
    let certified_data_path = [
        "canister".as_bytes(),
        canister_id,
        "certified_data".as_bytes(),
    ];

    let witness = match certificate.tree.lookup_path(&certified_data_path) {
        LookupResult::Found(witness) => witness,
        _ => {
            return false;
        }
    };

    let digest = tree.digest();
    if witness != digest {
        return false;
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_cbor::{CertificateToCbor, HashTreeToCbor};
    use ic_certification::hash_tree::HashTree;
    use ic_certification_testing::{CertificateBuilder, CertificateData};
    use ic_crypto_tree_hash::{flatmap, Label, LabeledTree};
    use ic_response_verification_test_utils::{
        create_canister_id, create_certified_data, AssetTree,
    };

    static CANISTER_ID: &str = "r7inp-6aaaa-aaaaa-aaabq-cai";
    static OTHER_CANISTER_ID: &str = "rdmx6-jaaaa-aaaaa-aaadq-cai";

    #[test]
    fn validate_tree_with_matching_digest() {
        let canister_id = create_canister_id(CANISTER_ID);
        let tree = AssetTree::default();
        let certified_data = tree.get_certified_data();

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key: _,
        } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
            .unwrap()
            .build()
            .unwrap();
        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();
        let tree = HashTree::from_cbor(&tree.serialize_to_cbor(None)).unwrap();

        let result = validate_tree(canister_id.as_ref(), &certificate, &tree);

        assert!(result);
    }

    #[test]
    fn validate_tree_with_mismatching_digest() {
        let canister_id = create_canister_id(CANISTER_ID);
        let tree = AssetTree::default();
        let certified_data = create_certified_data(
            "8160c07b45d617dba08a20eaa71ace28b5962965034b7539e42ebdb80da729a9",
        );

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key: _,
        } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
            .unwrap()
            .build()
            .unwrap();
        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();
        let tree = HashTree::from_cbor(&tree.serialize_to_cbor(None)).unwrap();

        let result = validate_tree(canister_id.as_ref(), &certificate, &tree);

        assert!(!result);
    }

    #[test]
    fn validate_tree_with_incorrect_canister_id() {
        let canister_id = create_canister_id(CANISTER_ID);
        let other_canister_id = create_canister_id(OTHER_CANISTER_ID);
        let tree = AssetTree::default();
        let certified_data = tree.get_certified_data();

        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key: _,
        } = CertificateBuilder::new(&other_canister_id.to_string(), &certified_data)
            .unwrap()
            .build()
            .unwrap();
        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();
        let tree = HashTree::from_cbor(&tree.serialize_to_cbor(None)).unwrap();

        let result = validate_tree(canister_id.as_ref(), &certificate, &tree);

        assert!(!result);
    }

    #[test]
    fn validate_tree_without_certified_data() {
        let canister_id = create_canister_id(CANISTER_ID);
        let tree = AssetTree::default();
        let certified_data = create_certified_data(
            "8160c07b45d617dba08a20eaa71ace28b5962965034b7539e42ebdb80da729a9",
        );

        let certificate_tree = LabeledTree::SubTree(flatmap![
            Label::from("canister") => LabeledTree::SubTree(flatmap![
                Label::from(canister_id.get_ref().to_vec()) => LabeledTree::SubTree(flatmap![
                    Label::from("garbage_data") => LabeledTree::Leaf(certified_data.to_vec()),
                ])
            ]),
        ]);
        let CertificateData {
            cbor_encoded_certificate,
            certificate: _,
            root_key: _,
        } = CertificateBuilder::from_custom_tree(certificate_tree)
            .build()
            .unwrap();
        let certificate = Certificate::from_cbor(&cbor_encoded_certificate).unwrap();
        let tree = HashTree::from_cbor(&tree.serialize_to_cbor(None)).unwrap();

        let result = validate_tree(canister_id.as_ref(), &certificate, &tree);

        assert!(!result);
    }
}
