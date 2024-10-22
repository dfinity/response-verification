use api::data_certificate;
use ic_cdk::{api::set_certified_data, *};
use ic_http_certification::{
    utils::add_v2_certificate_header, DefaultCelBuilder, DefaultFullCelExpression,
    DefaultResponseCertification, HttpCertification, HttpCertificationPath, HttpCertificationTree,
    HttpCertificationTreeEntry, HttpRequest, HttpResponse, HttpUpdateRequest, HttpUpdateResponse,
    CERTIFICATE_EXPRESSION_HEADER_NAME,
};
use lazy_static::lazy_static;
use std::{cell::RefCell, sync::Mutex};

thread_local! {
    // The current count
    static COUNT: RefCell<u32> = RefCell::new(0);

    // HTTP certification tree
    static HTTP_TREE: RefCell<HttpCertificationTree> = Default::default();
}

lazy_static! {
    // The CEL expression used to certify the count HTTP response
    static ref CEL_EXPR: DefaultFullCelExpression<'static> = {
        DefaultCelBuilder::full_certification()
            .with_request_headers(vec![])
            .with_request_query_parameters(vec![])
            .with_response_certification(DefaultResponseCertification::response_header_exclusions(
                vec![],
            ))
            .build()
    };

    // The string representation of the CEL expression
    static ref CEL_EXPR_STR: String = CEL_EXPR.to_string();

    // The current count as an HTTP response
    static ref COUNT_RESPONSE: Mutex<HttpResponse<'static>> = Mutex::new(create_response());

    static ref COUNT_RESPONSE_CERTIFICATION: Mutex<HttpCertification> = Mutex::new(create_certification(&COUNT_RESPONSE.lock().unwrap()));
}

// run when a canister is first installed
#[init]
fn init() {
    certify_response();

    // Set the certified data
    set_certified_data(&HTTP_TREE.with_borrow(|tree| tree.root_hash()));
}

// run every time a canister is upgraded
#[post_upgrade]
fn post_upgrade() {
    // run the same initialization logic
    init();
}

#[query]
fn http_request(req: HttpRequest<'static>) -> HttpResponse<'static> {
    if req.method() == "GET" {
        let mut response = COUNT_RESPONSE.lock().unwrap().clone();

        HTTP_TREE.with_borrow_mut(|http_tree| {
            add_v2_certificate_header(
                &data_certificate().unwrap(),
                &mut response,
                &http_tree
                    .witness(
                        &HttpCertificationTreeEntry::new(
                            HttpCertificationPath::exact("/"),
                            COUNT_RESPONSE_CERTIFICATION.lock().unwrap().clone(),
                        ),
                        &req.get_path().unwrap(),
                    )
                    .unwrap(),
                &HttpCertificationPath::exact("/").to_expr_path(),
            );
        });

        return response;
    }

    if req.method() == "POST" {
        return HttpResponse::builder().with_upgrade(true).build();
    }

    trap(&format!("Unsupported method: {}", req.method()));
}

#[update]
fn http_request_update(req: HttpUpdateRequest<'static>) -> HttpUpdateResponse<'static> {
    if req.method() == "GET" {
        return COUNT_RESPONSE.lock().unwrap().clone().into();
    }

    if req.method() == "POST" {
        COUNT.with_borrow_mut(|count| {
            *count += 1;
        });

        certify_response();

        return COUNT_RESPONSE.lock().unwrap().clone().into();
    }

    trap(&format!("Unsupported method: {}", req.method()));
}

fn certify_response() {
    HTTP_TREE.with_borrow_mut(|http_tree| {
        http_tree.delete(&HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact("/"),
            COUNT_RESPONSE_CERTIFICATION.lock().unwrap().clone(),
        ));

        let mut new_response = create_response();
        let new_certification = create_certification(&mut new_response);

        *COUNT_RESPONSE.lock().unwrap() = new_response;
        *COUNT_RESPONSE_CERTIFICATION.lock().unwrap() = new_certification;

        http_tree.insert(&HttpCertificationTreeEntry::new(
            HttpCertificationPath::exact("/"),
            new_certification,
        ));

        set_certified_data(&http_tree.root_hash());
    });
}

fn create_response() -> HttpResponse<'static> {
    let body = COUNT.with_borrow(|count| count.to_string().as_bytes().to_vec());

    let headers = vec![
        ("strict-transport-security".to_string(), "max-age=31536000; includeSubDomains".to_string()),
        ("x-frame-options".to_string(), "DENY".to_string()),
        ("x-content-type-options".to_string(), "nosniff".to_string()),
        ("content-security-policy".to_string(), "default-src 'self'; form-action 'self'; object-src 'none'; frame-ancestors 'none'; upgrade-insecure-requests; block-all-mixed-content".to_string()),
        ("referrer-policy".to_string(), "no-referrer".to_string()),
        ("permissions-policy".to_string(), "accelerometer=(),ambient-light-sensor=(),autoplay=(),battery=(),camera=(),display-capture=(),document-domain=(),encrypted-media=(),fullscreen=(),gamepad=(),geolocation=(),gyroscope=(),layout-animations=(self),legacy-image-formats=(self),magnetometer=(),microphone=(),midi=(),oversized-images=(self),payment=(),picture-in-picture=(),publickey-credentials-get=(),speaker-selection=(),sync-xhr=(self),unoptimized-images=(self),unsized-media=(self),usb=(),screen-wake-lock=(),web-share=(),xr-spatial-tracking=()".to_string()),
        ("cross-origin-embedder-policy".to_string(), "require-corp".to_string()),
        ("cross-origin-opener-policy".to_string(), "same-origin".to_string()),
        ("content-length".to_string(), body.len().to_string()),
        ("content-type".to_string(), "text/html".to_string()),
        (
            CERTIFICATE_EXPRESSION_HEADER_NAME.to_string(),
            CEL_EXPR_STR.to_string(),
        )
    ];

    HttpResponse::builder()
        .with_status_code(200)
        .with_headers(headers)
        .with_body(body)
        .build()
}

fn create_certification(response: &HttpResponse<'static>) -> HttpCertification {
    let request = HttpRequest::get("/").build();

    HttpCertification::full(&CEL_EXPR, &request, response, None).unwrap()
}
