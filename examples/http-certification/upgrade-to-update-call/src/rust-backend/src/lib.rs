use ic_cdk::*;
use ic_http_certification::{HttpResponse, HttpUpdateResponse};

#[query]
fn http_request() -> HttpResponse<'static> {
    HttpResponse::builder().with_upgrade(true).build()
}

#[update]
fn http_request_update() -> HttpUpdateResponse<'static> {
    HttpResponse::builder()
        .with_status_code(418)
        .with_body(b"I'm a teapot")
        .build_update()
}
