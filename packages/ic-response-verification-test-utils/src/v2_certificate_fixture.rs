use crate::{cbor_encode, create_versioned_certificate_header};
use ic_certification_testing::{CertificateBuilder, CertificateData};
use ic_http_certification::{HttpCertificationTree, HttpCertificationTreeEntry};
use ic_types::CanisterId;

pub struct V2TreeFixture {
    pub tree_cbor: Vec<u8>,
    pub certified_data: [u8; 32],
}

pub fn create_v2_tree_fixture(
    req_path: &str,
    certification_tree_entry: &HttpCertificationTreeEntry,
) -> V2TreeFixture {
    let mut tree = HttpCertificationTree::default();
    tree.insert(certification_tree_entry);

    let certified_data = tree.root_hash();
    let witness = tree.witness(certification_tree_entry, req_path).unwrap();
    let tree_cbor = cbor_encode(&witness);

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

pub fn create_v2_header(
    certification_tree_entry: &HttpCertificationTreeEntry,
    certificate_cbor: &[u8],
    tree_cbor: &[u8],
) -> String {
    create_versioned_certificate_header(
        certificate_cbor,
        tree_cbor,
        cbor_encode(&certification_tree_entry.path.to_expr_path()).as_slice(),
        2,
    )
}

pub struct V2Fixture {
    pub root_key: Vec<u8>,
    pub certificate_header: String,
    pub canister_id: CanisterId,
}

pub fn create_v2_fixture(
    req_path: &str,
    certification_tree_entry: &HttpCertificationTreeEntry,
    current_time: &u128,
) -> V2Fixture {
    let V2TreeFixture {
        tree_cbor,
        certified_data,
    } = create_v2_tree_fixture(req_path, certification_tree_entry);

    let V2CertificateFixture {
        root_key,
        certificate_cbor,
        canister_id,
    } = create_v2_certificate_fixture(&certified_data, current_time);

    let certificate_header =
        create_v2_header(certification_tree_entry, &certificate_cbor, &tree_cbor);

    V2Fixture {
        root_key,
        certificate_header,
        canister_id,
    }
}
