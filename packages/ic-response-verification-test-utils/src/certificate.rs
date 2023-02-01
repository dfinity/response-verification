use crate::AssetTree;
use ic_base_types::CanisterId;
use ic_certification_test_utils::CertificateData::{CanisterData, CustomTree};
use ic_certification_test_utils::{Certificate, CertificateBuilder};
use ic_crypto::threshold_sig_public_key_to_der;
use ic_crypto_tree_hash::{Digest, LabeledTree};
use std::str::FromStr;

pub fn create_canister_id(canister_id: &str) -> CanisterId {
    CanisterId::from_str(canister_id).unwrap()
}

pub struct CreateCertificateOptions {
    pub certificate_time: Option<u128>,
    pub canister_id: Option<CanisterId>,
    pub certified_data: Option<Digest>,
}

pub fn create_certificate(
    options: Option<CreateCertificateOptions>,
) -> (Certificate, Vec<u8>, Vec<u8>) {
    let default_certificate_time = 1651142233000005031;
    let certificate_time = options
        .as_ref()
        .and_then(|options| options.certificate_time)
        .unwrap_or(default_certificate_time);

    let default_canister_id = CanisterId::from_str("qoctq-giaaa-aaaaa-aaaea-cai").unwrap();
    let canister_id = options
        .as_ref()
        .and_then(|options| options.canister_id)
        .unwrap_or(default_canister_id);

    let default_certified_data = AssetTree::new().get_certified_data();
    let certified_data = options
        .as_ref()
        .and_then(|options| options.certified_data.clone())
        .unwrap_or(default_certified_data);

    let (certificate, root_key, cbor_encoded_certificate) = CertificateBuilder::new(CanisterData {
        canister_id,
        certified_data,
    })
    .with_time(u64::try_from(certificate_time).unwrap())
    .build();

    let der_encoded_key = threshold_sig_public_key_to_der(root_key).unwrap();

    (certificate, der_encoded_key, cbor_encoded_certificate)
}

pub fn create_custom_tree_certificate(
    tree: LabeledTree<Vec<u8>>,
) -> (Certificate, Vec<u8>, Vec<u8>) {
    let (certificate, root_key, cbor_encoded_certificate) =
        CertificateBuilder::new(CustomTree(tree)).build();

    let der_encoded_key = threshold_sig_public_key_to_der(root_key).unwrap();

    (certificate, der_encoded_key, cbor_encoded_certificate)
}

pub fn create_certificate_header(tree: &String, certificate: &String) -> String {
    format!("certificate=:{}:, tree=:{}:", certificate, tree)
}
