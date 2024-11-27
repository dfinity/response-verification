use ic_cdk::{
    api::{data_certificate, set_certified_data, time},
    *,
};
use ic_http_certification::{
    utils::{add_skip_certification_header, skip_certification_certified_data},
    HttpResponse, StatusCode,
};

#[init]
fn init() {
    set_certified_data(&skip_certification_certified_data());
}

#[query]
fn http_request() -> HttpResponse<'static> {
    let mut response = create_response();

    add_skip_certification_header(data_certificate().unwrap(), &mut response);

    response
}

fn create_response() -> HttpResponse<'static> {
    let body = format!(
        r#"
            <html>
                <head>
                    <title>ICP Skip Certification</title>
                </head>

                <body>
                    <h1>ICP Skip Certification</h1>
                    <p>This is an example of an IC canister that skips certification.</p>
                    <p>Current timestamp: {}<b>
                </body>
            </html>
        "#,
        time()
    )
    .as_bytes()
    .to_vec();

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
        ("content-type".to_string(), "text/html".to_string())
    ];

    HttpResponse::builder()
        .with_status_code(StatusCode::OK)
        .with_headers(headers)
        .with_body(body)
        .build()
}
