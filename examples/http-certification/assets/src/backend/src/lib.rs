use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ic_asset_certification::{Asset, AssetConfig, AssetFallbackConfig, AssetRouter};
use ic_cdk::{
    api::{data_certificate, set_certified_data},
    *,
};
use ic_certification::HashTree;
use ic_http_certification::{HttpCertificationTree, HttpRequest, HttpResponse};
use include_dir::{include_dir, Dir};
use serde::Serialize;
use std::cell::RefCell;

// Public methods

#[init]
fn init() {
    certify_all_assets();
}

#[post_upgrade]
fn post_upgrade() {
    init();
}

#[query]
fn http_request(req: HttpRequest) -> HttpResponse {
    asset_handler(&req)
}

thread_local! {
    static HTTP_TREE: RefCell<HttpCertificationTree> = RefCell::new(HttpCertificationTree::default());
    static ASSET_ROUTER: RefCell<AssetRouter<'static>> = RefCell::new(AssetRouter::new());
}

static ASSETS_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../frontend/dist");
const IMMUTABLE_ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

fn collect_assets<'a>(dir: &'a Dir, assets: &mut Vec<Asset<'a>>) {
    for file in dir.files() {
        assets.push(Asset::new(file.path().to_string_lossy(), file.contents()));
    }

    for dir in dir.dirs() {
        collect_assets(dir, assets);
    }
}

// Certification
fn certify_all_assets() {
    let asset_configs = vec![
        AssetConfig::File {
            path: "index.html".to_string(),
            content_type: Some("text/html".to_string()),
            headers: vec![(
                "cache-control".to_string(),
                "public, no-cache, no-store".to_string(),
            )],
            fallback_for: Some(AssetFallbackConfig {
                scope: "/".to_string(),
            }),
        },
        AssetConfig::Pattern {
            pattern: "**/*.js".to_string(),
            content_type: Some("text/javascript".to_string()),
            headers: vec![(
                "cache-control".to_string(),
                IMMUTABLE_ASSET_CACHE_CONTROL.to_string(),
            )],
        },
        AssetConfig::Pattern {
            pattern: "**/*.css".to_string(),
            content_type: Some("text/css".to_string()),
            headers: vec![(
                "cache-control".to_string(),
                IMMUTABLE_ASSET_CACHE_CONTROL.to_string(),
            )],
        },
        AssetConfig::Pattern {
            pattern: "**/*.ico".to_string(),
            content_type: Some("image/x-icon".to_string()),
            headers: vec![(
                "cache-control".to_string(),
                IMMUTABLE_ASSET_CACHE_CONTROL.to_string(),
            )],
        },
        AssetConfig::Pattern {
            pattern: "**/*.svg".to_string(),
            content_type: Some("image/svg+xml".to_string()),
            headers: vec![(
                "cache-control".to_string(),
                IMMUTABLE_ASSET_CACHE_CONTROL.to_string(),
            )],
        },
    ];

    let mut assets = Vec::new();
    collect_assets(&ASSETS_DIR, &mut assets);

    HTTP_TREE.with_borrow_mut(|http_tree| {
        ASSET_ROUTER.with_borrow_mut(|asset_router| {
            if let Err(err) = asset_router.certify_assets(http_tree, assets, asset_configs) {
                ic_cdk::trap(&format!("Failed to certify assets: {}", err));
            }
        });

        set_certified_data(&http_tree.root_hash());
    });
}

// Handlers
fn asset_handler(req: &HttpRequest) -> HttpResponse {
    HTTP_TREE.with_borrow(|http_tree| {
        ASSET_ROUTER.with_borrow(|asset_router| {
            if let Some((mut response, witness, expr_path)) =
                asset_router.serve_asset(http_tree, req)
            {
                add_certificate_header(&mut response, &witness, &expr_path);

                response
            } else {
                ic_cdk::trap("Failed to serve asset");
            }
        })
    })
}

const IC_CERTIFICATE_HEADER: &str = "IC-Certificate";
fn add_certificate_header(response: &mut HttpResponse, witness: &HashTree, expr_path: &[String]) {
    let certified_data = data_certificate().expect("No data certificate available");
    let witness = cbor_encode(witness);
    let expr_path = cbor_encode(&expr_path);

    response.headers.push((
        IC_CERTIFICATE_HEADER.to_string(),
        format!(
            "certificate=:{}:, tree=:{}:, expr_path=:{}:, version=2",
            BASE64.encode(certified_data),
            BASE64.encode(witness),
            BASE64.encode(expr_path)
        ),
    ));
}

// Encoding
fn cbor_encode(value: &impl Serialize) -> Vec<u8> {
    let mut serializer = serde_cbor::Serializer::new(Vec::new());
    serializer
        .self_describe()
        .expect("Failed to self describe CBOR");
    value
        .serialize(&mut serializer)
        .expect("Failed to serialize value");
    serializer.into_inner()
}
