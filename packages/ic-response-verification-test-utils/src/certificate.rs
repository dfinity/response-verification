use crate::base64_encode;
use ic_types::CanisterId;
use std::str::FromStr;

pub fn create_canister_id(canister_id: &str) -> CanisterId {
    CanisterId::from_str(canister_id).unwrap()
}

pub fn create_certificate_header(certificate: &[u8], tree: &[u8]) -> String {
    let certificate = base64_encode(certificate);
    let tree = base64_encode(tree);

    format!("certificate=:{}:, tree=:{}:", certificate, tree)
}

pub fn create_versioned_certificate_header(
    certificate: &[u8],
    tree: &[u8],
    expr_path: &[u8],
    version: u8,
) -> String {
    let certificate = base64_encode(certificate);
    let tree = base64_encode(tree);
    let expr_path = base64_encode(expr_path);

    format!(
        "certificate=:{}:, tree=:{}:, expr_path=:{}:, version={}",
        certificate, tree, expr_path, version
    )
}
