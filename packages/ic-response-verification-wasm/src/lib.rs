use ic_response_verification::ResponseVerificationJsError;
use ic_response_verification::types::CertificationResult;
use ic_response_verification::types::Request;
use ic_response_verification::types::Response;
use ic_response_verification::verify_request_response_pair as verify_request_response_pair_impl;
use ic_response_verification::{ MIN_VERIFICATION_VERSION, MAX_VERIFICATION_VERSION };
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "CertificationResult")]
    pub type JsCertificationResult;

    #[wasm_bindgen(typescript_type = "Request")]
    pub type JsRequest;

    #[wasm_bindgen(typescript_type = "Response")]
    pub type JsResponse;
}

#[wasm_bindgen(js_name = getMinVerificationVersion)]
pub fn get_min_verification_version() -> u8 {
    return MIN_VERIFICATION_VERSION;
}

#[wasm_bindgen(js_name = getMaxVerificationVersion)]
pub fn get_max_verification_version() -> u8 {
    return MAX_VERIFICATION_VERSION;
}

/// The primary entry point for verifying a request and response pair. This will verify the response
/// with respect to the request, according the [Response Verification Spec]().
#[wasm_bindgen(js_name = verifyRequestResponsePair)]
pub fn verify_request_response_pair(
    request: JsRequest,
    response: JsResponse,
    canister_id: &[u8],
    current_time_ns: u64,
    max_cert_time_offset_ns: u64,
    ic_public_key: &[u8],
    min_requested_verification_version: u8,
) -> Result<JsCertificationResult, ResponseVerificationJsError> {
    #[cfg(feature = "debug")]
    console_error_panic_hook::set_once();

    #[cfg(feature = "debug")]
    log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER).unwrap();

    let request = Request::from(JsValue::from(request));
    let response = Response::from(JsValue::from(response));

    verify_request_response_pair_impl(
        request.into(),
        response.into(),
        canister_id,
        current_time_ns as u128,
        max_cert_time_offset_ns as u128,
        ic_public_key,
        min_requested_verification_version,
    )
    .map(|certification_result| {
        JsValue::from(CertificationResult::from(certification_result)).unchecked_into::<JsCertificationResult>()
    })
    .map_err(|e| ResponseVerificationJsError::from(e))
}
