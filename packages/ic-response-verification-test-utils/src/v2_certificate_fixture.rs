use crate::{
    cbor_encode, create_expr_tree_path, create_versioned_certificate_header, hash, ExprTree,
};
use ic_certification::Hash;
use ic_certification_testing::{CertificateBuilder, CertificateData};
use ic_types::CanisterId;

pub struct V2TreeFixture {
    pub tree_cbor: Vec<u8>,
    pub certified_data: [u8; 32],
}

pub fn create_v2_tree_fixture(
    cel_expr: &str,
    expr_path: &[&str],
    req_hash: Option<&Hash>,
    res_hash: Option<&Hash>,
) -> V2TreeFixture {
    let cel_expr_hash = hash(cel_expr);

    let expr_tree_path = create_expr_tree_path(expr_path, &cel_expr_hash, req_hash, res_hash);

    let mut expr_tree = ExprTree::new();
    expr_tree.insert(&expr_tree_path);
    let certified_data = expr_tree.get_certified_data();
    let tree_cbor = expr_tree.witness_and_serialize_to_cbor(&expr_tree_path);

    V2TreeFixture {
        tree_cbor,
        certified_data,
    }
}

pub struct V2CertificateFixture {
    pub root_key: Vec<u8>,
    pub certificate_cbor: Vec<u8>,
    pub canister_id: CanisterId,
}

pub fn create_v2_certificate_fixture(
    certified_data: &[u8; 32],
    current_time: &u128,
) -> V2CertificateFixture {
    let canister_id = CanisterId::from_u64(5);

    let CertificateData {
        root_key,
        certificate: _,
        cbor_encoded_certificate,
    } = CertificateBuilder::new(&canister_id.to_string(), certified_data)
        .unwrap()
        .with_time(*current_time)
        .with_delegation(123, vec![(0, 10)])
        .build()
        .unwrap();

    V2CertificateFixture {
        root_key,
        certificate_cbor: cbor_encoded_certificate,
        canister_id,
    }
}

pub fn create_v2_header(expr_path: &[&str], certificate_cbor: &[u8], tree_cbor: &[u8]) -> String {
    let mut full_expr_path = vec!["http_expr"];
    full_expr_path.extend(expr_path);

    let certificate_header = create_versioned_certificate_header(
        certificate_cbor,
        tree_cbor,
        cbor_encode(&full_expr_path).as_slice(),
        2,
    );

    certificate_header
}

pub struct V2Fixture {
    pub root_key: Vec<u8>,
    pub certificate_header: String,
    pub canister_id: CanisterId,
}

pub fn create_v2_fixture(
    cel_expr: &str,
    expr_path: &[&str],
    current_time: &u128,
    req_hash: Option<&Hash>,
    res_hash: Option<&Hash>,
) -> V2Fixture {
    let V2TreeFixture {
        tree_cbor,
        certified_data,
    } = create_v2_tree_fixture(cel_expr, expr_path, req_hash, res_hash);

    let V2CertificateFixture {
        root_key,
        certificate_cbor,
        canister_id,
    } = create_v2_certificate_fixture(&certified_data, current_time);

    let certificate_header = create_v2_header(expr_path, &certificate_cbor, &tree_cbor);

    V2Fixture {
        root_key,
        certificate_header,
        canister_id,
    }
}
