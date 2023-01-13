#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
extern crate console_error_panic_hook;

#[cfg(target_arch = "wasm32")]
use std::panic;

#[cfg(target_arch = "wasm32")]
use error::ResponseVerificationJsError;

use body::decode_body_to_sha256;
use cbor::{certificate::CertificateToCbor, hash_tree::HashTreeToCbor, parse_cbor_string_array};
use certificate_header::CertificateHeader;
use error::ResponseVerificationError;
use error::ResponseVerificationResult;
use http::Uri;
use ic_certification::{Certificate, HashTree};
use types::{Request, Response};
use validation::{validate_body, validate_certificate_time, validate_tree};

pub mod cel;
pub mod hash;
pub mod types;

mod body;
mod cbor;
mod certificate_header;
mod certificate_header_field;
mod error;
mod logger;
mod test_utils;
mod validation;

pub const MIN_VERIFICATION_VERSION: u8 = 1;
pub const MAX_VERIFICATION_VERSION: u8 = 2;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyRequestResponsePair)]
pub fn verify_request_response_pair(
    request: JsValue,
    response: JsValue,
    canister_id: &[u8],
    current_time_ns: u64,
    max_cert_time_offset_ns: u64,
) -> Result<bool, ResponseVerificationJsError> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    let request = Request::from(request);
    let response = Response::from(response);

    verify_request_response_pair_impl(
        request,
        response,
        canister_id,
        current_time_ns as u128,
        max_cert_time_offset_ns as u128,
    )
    .map_err(|e| ResponseVerificationJsError::from(e))
}

#[cfg(not(target_arch = "wasm32"))]
pub use verify_request_response_pair_impl as verify_request_response_pair;

pub fn verify_request_response_pair_impl(
    request: Request,
    response: Response,
    canister_id: &[u8],
    current_time_ns: u128,
    max_cert_time_offset_ns: u128,
) -> ResponseVerificationResult<bool> {
    let mut encoding: Option<String> = None;
    let mut tree: Option<HashTree> = None;
    let mut certificate: Option<Certificate> = None;
    let mut version = MIN_VERIFICATION_VERSION;
    let mut _expr_path: Option<Vec<String>> = None;

    for (name, value) in response.headers.iter() {
        if name.eq_ignore_ascii_case("Ic-Certificate") {
            let certificate_header = CertificateHeader::from(value.as_str());

            tree = certificate_header
                .tree
                .and_then(|tree| Some(HashTree::from_cbor(tree)))
                .transpose()?;

            certificate = certificate_header
                .certificate
                .and_then(|certificate| Some(Certificate::from_cbor(certificate)))
                .transpose()?;

            version = certificate_header
                .version
                .unwrap_or(MIN_VERIFICATION_VERSION);

            _expr_path = certificate_header
                .expr_path
                .and_then(|expr_path| Some(parse_cbor_string_array(&expr_path, "expr_path")))
                .transpose()?;
        }

        if name.eq_ignore_ascii_case("Content-Encoding") {
            encoding = Some(value.into());
        }
    }

    verification(
        version,
        request,
        response,
        canister_id,
        current_time_ns,
        max_cert_time_offset_ns,
        tree,
        certificate,
        encoding,
    )
}

fn verification(
    version: u8,
    request: Request,
    response: Response,
    canister_id: &[u8],
    current_time_ns: u128,
    max_cert_time_offset_ns: u128,
    tree: Option<HashTree>,
    certificate: Option<Certificate>,
    encoding: Option<String>,
) -> ResponseVerificationResult<bool> {
    match version {
        1 => v1_verification(
            request,
            response,
            canister_id,
            current_time_ns,
            max_cert_time_offset_ns,
            tree,
            certificate,
            encoding,
        ),
        2 => v2_verification(
            request,
            response,
            canister_id,
            current_time_ns,
            max_cert_time_offset_ns,
            tree,
            certificate,
            encoding,
        ),
        _ => Err(ResponseVerificationError::UnsupportedVerificationVersion {
            min_supported_version: MIN_VERIFICATION_VERSION,
            max_supported_version: MAX_VERIFICATION_VERSION,
            requested_version: version,
        }),
    }
}

fn v1_verification(
    request: Request,
    response: Response,
    canister_id: &[u8],
    current_time_ns: u128,
    max_cert_time_offset_ns: u128,
    tree: Option<HashTree>,
    certificate: Option<Certificate>,
    encoding: Option<String>,
) -> ResponseVerificationResult<bool> {
    let request_uri = request
        .url
        .parse::<Uri>()
        .map_err(|_| ResponseVerificationError::MalformedUrl(request.url))?;

    return if let (Some(tree), Some(certificate)) = (tree, certificate) {
        let body_sha = decode_body_to_sha256(response.body.as_slice(), encoding).unwrap();

        validate_certificate_time(&certificate, &current_time_ns, &max_cert_time_offset_ns)?;
        // [TODO] - validate_certificate
        let result = validate_tree(&canister_id, &certificate, &tree)
            && validate_body(&tree, &request_uri, &body_sha);

        Ok(result)
    } else {
        Ok(false)
    };
}

fn v2_verification(
    _request: Request,
    _response: Response,
    _canister_id: &[u8],
    _current_time_ns: u128,
    _max_cert_time_offset_ns: u128,
    _tree: Option<HashTree>,
    _certificate: Option<Certificate>,
    _encoding: Option<String>,
) -> ResponseVerificationResult<bool> {
    panic!("v2 response verification has not been implemented yet")
}
