#![deny(clippy::all)]

use crate::request::request_from_js;
use crate::response::response_from_js;
use ic_response_verification::{
    types::VerificationInfo, verify_request_response_pair as verify_request_response_pair_impl,
    ResponseVerificationJsError, MAX_VERIFICATION_VERSION, MIN_VERIFICATION_VERSION,
};
use wasm_bindgen::{prelude::*, JsCast};

mod request;
mod response;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "VerificationInfo")]
    pub type JsVerificationInfo;

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

#[wasm_bindgen(start)]
pub fn main_js() {
    console_error_panic_hook::set_once();
    log::set_logger(&wasm_bindgen_console_logger::DEFAULT_LOGGER).unwrap();
    log::set_max_level(log::LevelFilter::Trace);
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
) -> Result<JsVerificationInfo, ResponseVerificationJsError> {
    let request = request_from_js(JsValue::from(request));
    let response = response_from_js(JsValue::from(response));

    verify_request_response_pair_impl(
        request.into(),
        response.into(),
        canister_id,
        current_time_ns as u128,
        max_cert_time_offset_ns as u128,
        ic_public_key,
        min_requested_verification_version,
    )
    .map(|verification_result| {
        JsValue::from(VerificationInfo::from(verification_result))
            .unchecked_into::<JsVerificationInfo>()
    })
    .map_err(|e| ResponseVerificationJsError::from(e))
}
