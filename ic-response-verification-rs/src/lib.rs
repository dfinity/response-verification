#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
extern crate console_error_panic_hook;

#[cfg(target_arch = "wasm32")]
use std::panic;

use body::decode_body_to_sha256;
use canister_id::resolve_canister_id;
use certificate::CertificateToCbor;
use certificate_header::CertificateHeader;
use error::ResponseVerificationError;
use hash_tree::HashTreeToCbor;
use http::Uri;
use ic_certification::{Certificate, HashTree};
use request::Request;
use response::Response;
use validation::{validate_body, validate_tree};

pub mod request;
pub mod response;

mod body;
mod canister_id;
mod cbor;
mod certificate;
mod certificate_header;
mod certificate_header_field;
mod error;
mod hash_tree;
mod logger;
mod validation;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyRequestResponsePair)]
pub fn verify_request_response_pair(
    request: JsValue,
    response: JsValue,
) -> Result<bool, ResponseVerificationError> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    let request = Request::from(request);
    let response = Response::from(response);

    verify_request_response_pair_impl(request, response)
}

#[cfg(not(target_arch = "wasm32"))]
pub use verify_request_response_pair_impl as verify_request_response_pair;

pub fn verify_request_response_pair_impl(
    request: Request,
    response: Response,
) -> Result<bool, ResponseVerificationError> {
    let mut encoding: Option<String> = None;
    let mut tree: Option<HashTree> = None;
    let mut certificate: Option<Certificate> = None;

    for (name, value) in response.headers {
        if name.eq_ignore_ascii_case("Ic-Certificate") {
            let certificate_header = CertificateHeader::from(value.as_str());

            if let Some(parsed_tree) = certificate_header.tree {
                tree = match HashTree::from_cbor(parsed_tree) {
                    Ok(tree) => Some(tree),
                    Err(_) => return Ok(false),
                }
            }

            if let Some(certificate_cbor) = certificate_header.certificate {
                certificate = match Certificate::from_cbor(certificate_cbor) {
                    Ok(certificate) => Some(certificate),
                    Err(_) => return Ok(false),
                }
            }
        }

        if name.eq_ignore_ascii_case("Content-Encoding") {
            encoding = Some(value);
        }
    }

    let request_uri = request
        .url
        .parse::<Uri>()
        .map_err(|_| ResponseVerificationError::InvalidUrl(request.url))?;
    let host_uri = request
        .headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        .and_then(|(_, host)| host.parse::<Uri>().ok());
    let canister_id = resolve_canister_id(&request_uri, host_uri.as_ref());

    return if let (Some(tree), Some(certificate), Some(canister_id)) =
        (tree, certificate, canister_id)
    {
        let body_sha = decode_body_to_sha256(response.body.as_slice(), encoding).unwrap();

        let result = validate_tree(&canister_id, &certificate, &tree)
            && validate_body(&tree, &request_uri, &body_sha);

        Ok(result)
    } else {
        Ok(false)
    };
}
