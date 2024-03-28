use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ic_cdk::{
    api::{data_certificate, set_certified_data},
    *,
};
use ic_http_certification::{
    DefaultCelBuilder, DefaultResponseCertification, DefaultResponseOnlyCelExpression, HeaderField,
    HttpCertification, HttpCertificationPath, HttpCertificationTree, HttpCertificationTreeEntry,
    HttpRequest, HttpResponse,
};
use include_dir::{include_dir, Dir};
use lazy_static::lazy_static;
use serde::Serialize;
use std::{borrow::Cow, cell::RefCell, collections::HashMap};

// Public methods

#[init]
fn init() {
    prepare_cel_exprs();
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

// Storage

#[derive(Debug, Clone)]
struct HttpAssetResponse<'a> {
    pub status_code: u16,
    pub headers: Vec<HeaderField>,
    pub body: Cow<'a, [u8]>,
}

impl Into<HttpResponse> for HttpAssetResponse<'_> {
    fn into(self) -> HttpResponse {
        HttpResponse {
            status_code: self.status_code,
            headers: self.headers,
            body: self.body.to_vec(),
            upgrade: None,
        }
    }
}

struct CertifiedHttpResponse<'a> {
    response: HttpAssetResponse<'a>,
    certification: HttpCertification,
}

thread_local! {
    static HTTP_TREE: RefCell<HttpCertificationTree> = RefCell::new(HttpCertificationTree::default());
    static ENCODED_RESPONSES: RefCell<HashMap<(String, String), CertifiedHttpResponse<'static>>> = RefCell::new(HashMap::new());
    static RESPONSES: RefCell<HashMap<String, CertifiedHttpResponse<'static>>> = RefCell::new(HashMap::new());
    static CEL_EXPRS: RefCell<HashMap<String, (DefaultResponseOnlyCelExpression<'static>, String)>> = RefCell::new(HashMap::new());
}

static ASSETS_DIR: Dir<'_> = include_dir!("$CARGO_MANIFEST_DIR/../frontend/dist");

lazy_static! {
    static ref ASSET_CEL_EXPR_PATH: &'static str = "assets";
    static ref INDEX_REQ_PATH: &'static str = "";
    static ref INDEX_TREE_PATH: HttpCertificationPath<'static> =
        HttpCertificationPath::wildcard(*INDEX_REQ_PATH);
    static ref INDEX_FILE_PATH: &'static str = "index.html";
}

// Certification

fn prepare_cel_exprs() {
    let asset_cel_expr_def = DefaultCelBuilder::response_only_certification()
        .with_response_certification(DefaultResponseCertification::response_header_exclusions(
            vec![],
        ))
        .build();

    let asset_cel_expr = asset_cel_expr_def.to_string();

    CEL_EXPRS.with_borrow_mut(|exprs| {
        exprs.insert(
            ASSET_CEL_EXPR_PATH.to_string(),
            (asset_cel_expr_def, asset_cel_expr),
        );
    });
}

fn certify_all_assets() {
    certify_index_asset();
    certify_asset_glob("assets/**/*.css", "text/css");
    certify_asset_glob("assets/**/*.js", "text/javascript");
    certify_asset_glob("assets/**/*.ico", "image/x-icon");
    certify_asset_glob("assets/**/*.svg", "image/svg+xml");
}

fn certify_index_asset() {
    let additional_headers = vec![
        ("content-type".to_string(), "text/html".to_string()),
        (
            "cache-control".to_string(),
            "public, no-cache, no-store".to_string(),
        ),
    ];

    let identity_file = ASSETS_DIR
        .get_file(*INDEX_FILE_PATH)
        .expect("No index.html file found!!!");
    let body = identity_file.contents();

    certify_asset(
        body,
        INDEX_FILE_PATH.to_string(),
        &*INDEX_TREE_PATH,
        INDEX_REQ_PATH.to_string(),
        additional_headers,
    );
}

fn certify_asset_glob(glob: &str, content_type: &str) {
    // iterate over every asset matching the glob
    for identity_file in ASSETS_DIR
        .find(glob)
        .unwrap()
        .map(|entry| entry.as_file().unwrap())
    {
        // compute the different paths needed for this asset
        let asset_file_path = identity_file.path().to_str().unwrap().to_string();
        let asset_req_path = if !asset_file_path.starts_with("/") {
            format!("/{}", asset_file_path)
        } else {
            asset_file_path.clone()
        };
        let asset_tree_path = HttpCertificationPath::exact(&asset_req_path);

        // add the content-type and cache-control headers
        let additional_headers = vec![
            ("content-type".to_string(), content_type.to_string()),
            (
                "cache-control".to_string(),
                "public, max-age=31536000, immutable".to_string(),
            ),
        ];

        let body = identity_file.contents();
        certify_asset(
            body,
            asset_file_path.to_string(),
            &asset_tree_path,
            asset_req_path.to_string(),
            additional_headers,
        );
    }
}

fn certify_asset(
    body: &'static [u8],
    asset_file_path: String,
    asset_tree_path: &HttpCertificationPath,
    asset_req_path: String,
    additional_headers: Vec<HeaderField>,
) {
    certify_asset_response(
        body,
        additional_headers.clone(),
        asset_tree_path,
        asset_req_path.to_string(),
    );
    certify_asset_with_encoding(
        &asset_file_path,
        asset_tree_path,
        asset_req_path.to_string(),
        "gzip",
        additional_headers.clone(),
    );
    certify_asset_with_encoding(
        &asset_file_path,
        asset_tree_path,
        asset_req_path.to_string(),
        "br",
        additional_headers,
    );
}

fn certify_asset_with_encoding(
    asset_file_path: &str,
    asset_tree_path: &HttpCertificationPath,
    asset_req_path: String,
    encoding: &str,
    additional_headers: Vec<HeaderField>,
) {
    // check if the file exists before certifying it
    if let Some(file) = ASSETS_DIR.get_file(format!("{}.{}", asset_file_path, encoding)) {
        let body = file.contents();

        // add the content encoding header
        let mut headers = vec![("content-encoding".to_string(), encoding.to_string())];
        headers.extend(additional_headers);

        CEL_EXPRS.with_borrow(|cel_exprs| {
            // get the relevant CEL expression
            let (cel_expr_def, cel_expr_str) = cel_exprs.get(*ASSET_CEL_EXPR_PATH).unwrap();

            // create the response
            let response = create_asset_response(headers, body, cel_expr_str.to_string());

            // certify the response
            let certification =
                HttpCertification::response_only(cel_expr_def, &response.clone().into(), None)
                    .unwrap();

            ENCODED_RESPONSES.with_borrow_mut(|responses| {
                // store the response for later retrieval
                responses.insert(
                    (asset_req_path, encoding.to_string()),
                    CertifiedHttpResponse {
                        response,
                        certification: certification.clone(),
                    },
                );
            });

            HTTP_TREE.with_borrow_mut(|http_tree| {
                // add the certification to the certification tree
                http_tree.insert(&HttpCertificationTreeEntry::new(
                    asset_tree_path,
                    &certification,
                ));

                // set the canister's certified data
                set_certified_data(&http_tree.root_hash());
            });
        });
    };
}

const IC_CERTIFICATE_EXPRESSION_HEADER: &str = "IC-CertificateExpression";
fn certify_asset_response(
    body: &'static [u8],
    additional_headers: Vec<HeaderField>,
    asset_tree_path: &HttpCertificationPath,
    asset_req_path: String,
) {
    CEL_EXPRS.with_borrow(|cel_exprs| {
        // get the relevant CEL expression
        let (cel_expr_def, cel_expr_str) = cel_exprs.get(*ASSET_CEL_EXPR_PATH).unwrap();

        // create the response
        let response = create_asset_response(additional_headers, body, cel_expr_str.to_string());

        // certify the response
        let certification =
            HttpCertification::response_only(cel_expr_def, &response.clone().into(), None).unwrap();

        RESPONSES.with_borrow_mut(|responses| {
            // store the response for later retrieval
            responses.insert(
                asset_req_path,
                CertifiedHttpResponse {
                    response,
                    certification: certification.clone(),
                },
            );
        });

        HTTP_TREE.with_borrow_mut(|http_tree| {
            // add the certification to the certification tree
            http_tree.insert(&HttpCertificationTreeEntry::new(
                asset_tree_path,
                &certification,
            ));

            // set the canister's certified data
            set_certified_data(&http_tree.root_hash());
        });
    });
}

// Handlers
fn asset_handler(req: &HttpRequest) -> HttpResponse {
    let req_path = req.get_path().expect("Failed to get req path");

    RESPONSES.with_borrow(|responses| {
        ENCODED_RESPONSES.with_borrow(|encoded_responses| {
            let (asset_req_path, asset_tree_path, identity_response) =
            // if the requested path matches a static asset, serve that
            if let Some(identity_response) = responses.get(&req_path) {
                (
                    req_path.to_string(),
                    HttpCertificationPath::exact(&req_path),
                    identity_response,
                )
            // otherwise serve the index.html
            } else {
                (
                    INDEX_REQ_PATH.to_string(),
                    INDEX_TREE_PATH.to_owned(),
                    responses.get(*INDEX_REQ_PATH).unwrap(),
                )
            };

            // extract the content encoding header
            let content_encoding = req.headers.iter().find_map(|(name, value)| {
                if name.to_lowercase() == "accept-encoding" {
                    Some(value)
                } else {
                    None
                }
            });

            let CertifiedHttpResponse {
                certification,
                response,
            } = content_encoding
                .and_then(|encoding| {
                    // if the request asks for Brotli and it's available for this file, serve that version
                    if encoding.contains("br") {
                        if let Some(br_response) =
                            encoded_responses.get(&(asset_req_path.clone(), "br".to_string()))
                        {
                            return Some(br_response);
                        }
                    }

                    // if the request asks for Gzip and it's available for this file, serve that version
                    if encoding.contains("gzip") {
                        if let Some(gzip_response) =
                            encoded_responses.get(&(asset_req_path, "gzip".to_string()))
                        {
                            return Some(gzip_response);
                        }
                    }

                    None
                })
                // otherwise serve the identity version
                .unwrap_or(identity_response);

            let mut response: HttpResponse = response.clone().into();

            add_certificate_header(
                &mut response,
                &HttpCertificationTreeEntry::new(&asset_tree_path, certification),
                &req_path,
                &asset_tree_path.to_expr_path(),
            );

            response
        })
    })
}

const IC_CERTIFICATE_HEADER: &str = "IC-Certificate";
fn add_certificate_header(
    response: &mut HttpResponse,
    entry: &HttpCertificationTreeEntry,
    request_url: &str,
    expr_path: &[String],
) {
    let certified_data = data_certificate().expect("No data certificate available");
    let witness = HTTP_TREE.with_borrow(|http_tree| {
        let witness = http_tree.witness(entry, request_url).unwrap();

        cbor_encode(&witness)
    });
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

fn create_asset_response(
    additional_headers: Vec<HeaderField>,
    body: &[u8],
    cel_expr: String,
) -> HttpAssetResponse {
    // set up the default headers and include additional headers provided by the caller
    let mut headers = vec![
        ("strict-transport-security".to_string(), "max-age=31536000; includeSubDomains".to_string()),
        ("x-frame-options".to_string(), "DENY".to_string()),
        ("x-content-type-options".to_string(), "nosniff".to_string()),
        ("content-security-policy".to_string(), "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content".to_string()),
        ("referrer-policy".to_string(), "no-referrer".to_string()),
        ("permissions-policy".to_string(), "accelerometer=(),ambient-light-sensor=(),autoplay=(),battery=(),camera=(),display-capture=(),document-domain=(),encrypted-media=(),fullscreen=(),gamepad=(),geolocation=(),gyroscope=(),layout-animations=(self),legacy-image-formats=(self),magnetometer=(),microphone=(),midi=(),oversized-images=(self),payment=(),picture-in-picture=(),publickey-credentials-get=(),speaker-selection=(),sync-xhr=(self),unoptimized-images=(self),unsized-media=(self),usb=(),screen-wake-lock=(),web-share=(),xr-spatial-tracking=()".to_string()),
        ("cross-origin-embedder-policy".to_string(), "require-corp".to_string()),
        ("cross-origin-opener-policy".to_string(), "same-origin".to_string()),
        ("content-length".to_string(), body.len().to_string()),
        (IC_CERTIFICATE_EXPRESSION_HEADER.to_string(), cel_expr),
    ];
    headers.extend(additional_headers);

    HttpAssetResponse {
        status_code: 200,
        headers,
        body: Cow::Borrowed(body),
    }
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
