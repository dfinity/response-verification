use http::StatusCode;
use ic_asset_certification::{Asset, AssetConfig, AssetEncoding, AssetRouter, ASSET_CHUNK_SIZE};
use ic_certification_testing::{CertificateBuilder, CertificateData};
use ic_http_certification::{
    DefaultCelBuilder, DefaultResponseCertification, HeaderField, HttpRequest, HttpResponse,
};
use ic_response_verification::verify_request_response_pair;
use ic_response_verification_test_utils::{create_canister_id, get_current_timestamp};
use once_cell::sync::OnceCell;
use rstest::*;

mod common;
use common::*;

const ASSET_ONE_NAME: &str = "asset_one";
const ASSET_ONE_SIZE: usize = ASSET_CHUNK_SIZE + 1;

const MAX_CERT_TIME_OFFSET_NS: u128 = 300_000_000_000;
const MIN_REQUESTED_VERIFICATION_VERSION: u8 = 2;

#[rstest]
fn should_certify_long_asset_chunkwise(
    asset_one_body: &'static [u8],
    asset_one_chunk_one: &'static [u8],
    asset_one_chunk_two: &'static [u8],
) {
    let current_time = get_current_timestamp();
    let canister_id = create_canister_id("rdmx6-jaaaa-aaaaa-aaadq-cai");
    let req_url = format!("/{}", ASSET_ONE_NAME);

    let mut asset_router = AssetRouter::default();
    let assets = [Asset::new(ASSET_ONE_NAME, asset_one_body)];
    let asset_configs = [asset_config(ASSET_ONE_NAME.to_string(), vec![])];
    asset_router.certify_assets(assets, asset_configs).unwrap();

    let certified_data = asset_router.root_hash();
    let CertificateData {
        cbor_encoded_certificate,
        certificate: _,
        root_key,
    } = CertificateBuilder::new(&canister_id.to_string(), &certified_data)
        .expect("Failed to create CertificateBuilder")
        .with_time(current_time)
        .build()
        .expect("Failed to create CertificateData from CertificateBuilder");

    let mut expected_headers = common_asset_headers();
    expected_headers.extend(vec![
        ("content-type".to_string(), "text/html".to_string()),
        ("content-length".to_string(), ASSET_CHUNK_SIZE.to_string()),
        (
            "content-range".to_string(),
            format!("bytes 0-{}/{}", ASSET_CHUNK_SIZE - 1, ASSET_ONE_SIZE),
        ),
    ]);
    let expected_chunk_one_res = HttpResponse::builder()
        .with_status_code(StatusCode::PARTIAL_CONTENT)
        .with_headers(expected_headers)
        .with_body(asset_one_chunk_one)
        .build();

    let chunk_one_req = HttpRequest::get(&req_url).build();
    let chunk_one_res = asset_router
        .serve_asset(&cbor_encoded_certificate, &chunk_one_req)
        .unwrap();
    assert_response_eq!(chunk_one_res, expected_chunk_one_res);

    let chunk_one_verification = verify_request_response_pair(
        chunk_one_req,
        chunk_one_res,
        canister_id.as_ref(),
        current_time,
        MAX_CERT_TIME_OFFSET_NS,
        &root_key,
        MIN_REQUESTED_VERIFICATION_VERSION,
    )
    .unwrap();
    assert_eq!(chunk_one_verification.verification_version, 2);
    assert_verified_response_eq!(
        chunk_one_verification.response.unwrap(),
        expected_chunk_one_res
    );

    let mut expected_headers = common_asset_headers();
    expected_headers.extend(vec![
        ("content-type".to_string(), "text/html".to_string()),
        (
            "content-length".to_string(),
            (ASSET_ONE_SIZE - ASSET_CHUNK_SIZE).to_string(),
        ),
        (
            "content-range".to_string(),
            format!(
                "bytes {}-{}/{}",
                ASSET_CHUNK_SIZE,
                ASSET_ONE_SIZE - 1,
                ASSET_ONE_SIZE
            ),
        ),
    ]);
    let expected_chunk_two_res = HttpResponse::builder()
        .with_status_code(StatusCode::PARTIAL_CONTENT)
        .with_headers(expected_headers)
        .with_body(asset_one_chunk_two)
        .build();

    let chunk_two_req = HttpRequest::get(&req_url)
        .with_headers(vec![(
            "range".to_string(),
            format!("bytes={}-", ASSET_CHUNK_SIZE),
        )])
        .build();
    let chunk_two_res = asset_router
        .serve_asset(&cbor_encoded_certificate, &chunk_two_req)
        .unwrap();
    assert_response_eq!(chunk_two_res, expected_chunk_two_res);

    let chunk_two_verification = verify_request_response_pair(
        chunk_two_req,
        chunk_two_res,
        canister_id.as_ref(),
        current_time,
        MAX_CERT_TIME_OFFSET_NS,
        &root_key,
        MIN_REQUESTED_VERIFICATION_VERSION,
    )
    .unwrap();
    assert_eq!(chunk_two_verification.verification_version, 2);
    assert_verified_response_eq!(
        chunk_two_verification.response.unwrap(),
        expected_chunk_two_res
    );
}

#[fixture]
fn asset_cel_expr() -> String {
    DefaultCelBuilder::full_certification()
        .with_response_certification(DefaultResponseCertification::response_header_exclusions(
            vec![],
        ))
        .build()
        .to_string()
}

#[fixture]
fn asset_range_cel_expr() -> String {
    DefaultCelBuilder::full_certification()
        .with_request_headers(vec!["range"])
        .with_response_certification(DefaultResponseCertification::response_header_exclusions(
            vec![],
        ))
        .build()
        .to_string()
}

#[fixture]
fn asset_one_body() -> &'static [u8] {
    static ASSET_ONE_BODY: OnceCell<Vec<u8>> = OnceCell::new();

    ASSET_ONE_BODY.get_or_init(|| asset_body(ASSET_ONE_NAME, ASSET_ONE_SIZE))
}

#[fixture]
fn asset_one_chunk_one(asset_one_body: &'static [u8]) -> &'static [u8] {
    static ASSET_ONE_CHUNK: OnceCell<&[u8]> = OnceCell::new();

    ASSET_ONE_CHUNK.get_or_init(|| asset_chunk(asset_one_body, 0))
}

#[fixture]
fn asset_one_chunk_two(asset_one_body: &'static [u8]) -> &'static [u8] {
    static ASSET_ONE_CHUNK: OnceCell<&[u8]> = OnceCell::new();

    ASSET_ONE_CHUNK.get_or_init(|| asset_chunk(asset_one_body, 1))
}

fn asset_config(path: String, encodings: Vec<(AssetEncoding, String)>) -> AssetConfig {
    AssetConfig::File {
        path,
        content_type: Some("text/html".to_string()),
        headers: common_asset_headers(),
        fallback_for: vec![],
        aliased_by: vec![],
        encodings,
    }
}

fn common_asset_headers() -> Vec<HeaderField> {
    vec![(
        "cache-control".to_string(),
        "public, no-cache, no-store".to_string(),
    )]
}
