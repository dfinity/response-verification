#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;

#[cfg(target_arch = "wasm32")]
extern crate console_error_panic_hook;

#[cfg(target_arch = "wasm32")]
use std::panic;

#[cfg(target_arch = "wasm32")]
use error::ResponseVerificationJsError;

use crate::body::decode_body;
use crate::hash::{filter_response_headers, hash};
use crate::types::CertificationResult;
use crate::validation::{validate_expr_hash, validate_expr_path, VerifyCertificate};
use cbor::{certificate::CertificateToCbor, hash_tree::HashTreeToCbor, parse_cbor_string_array};
use certificate_header::CertificateHeader;
use error::ResponseVerificationError;
use error::ResponseVerificationResult;
use ic_certification::hash_tree::Sha256Digest;
use ic_certification::{Certificate, HashTree};
use types::{Certification, Request, Response};
use validation::{validate_body, validate_certificate_time, validate_hashes, validate_tree};

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
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "CertificationResult")]
    pub type JsCertificationResult;

    #[wasm_bindgen(typescript_type = "Request")]
    pub type JsRequest;

    #[wasm_bindgen(typescript_type = "Response")]
    pub type JsResponse;
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen(js_name = verifyRequestResponsePair)]
pub fn verify_request_response_pair(
    request: JsRequest,
    response: JsResponse,
    canister_id: &[u8],
    current_time_ns: u64,
    max_cert_time_offset_ns: u64,
    ic_public_key: &[u8],
) -> Result<JsCertificationResult, ResponseVerificationJsError> {
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    let request = Request::from(JsValue::from(request));
    let response = Response::from(JsValue::from(response));

    verify_request_response_pair_impl(
        request,
        response,
        canister_id,
        current_time_ns as u128,
        max_cert_time_offset_ns as u128,
        ic_public_key,
    )
    .map(|certification_result| {
        JsValue::from(certification_result).unchecked_into::<JsCertificationResult>()
    })
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
    ic_public_key: &[u8],
) -> ResponseVerificationResult<CertificationResult> {
    let mut encoding: Option<String> = None;
    let mut tree: Option<HashTree> = None;
    let mut certificate: Option<Certificate> = None;
    let mut version = MIN_VERIFICATION_VERSION;
    let mut expr_path: Option<Vec<String>> = None;
    let mut certification: Option<Certification> = None;
    let mut expr_hash: Option<Sha256Digest> = None;

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

            expr_path = certificate_header
                .expr_path
                .and_then(|expr_path| Some(parse_cbor_string_array(&expr_path, "expr_path")))
                .transpose()?;
        }

        if name.eq_ignore_ascii_case("Ic-Certificate-Expression") {
            certification = cel::cel_to_certification(value)?;
            expr_hash = Some(hash(value.as_bytes()));
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
        expr_path,
        expr_hash,
        certification,
        ic_public_key,
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
    expr_path: Option<Vec<String>>,
    expr_hash: Option<Sha256Digest>,
    certification: Option<Certification>,
    ic_public_key: &[u8],
) -> ResponseVerificationResult<CertificationResult> {
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
            ic_public_key,
        ),
        2 => v2_verification(
            request,
            response,
            canister_id,
            current_time_ns,
            max_cert_time_offset_ns,
            tree,
            certificate,
            expr_path,
            expr_hash,
            certification,
            ic_public_key,
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
    ic_public_key: &[u8],
) -> ResponseVerificationResult<CertificationResult> {
    match (tree, certificate) {
        (Some(tree), Some(certificate)) => {
            validate_certificate_time(&certificate, &current_time_ns, &max_cert_time_offset_ns)?;
            certificate.verify(&canister_id, &ic_public_key)?;

            let request_uri = &request.get_uri()?;
            let decoded_body = decode_body(&response.body, &encoding).unwrap();
            let decoded_body_sha = hash(decoded_body.as_slice());
            let valid_tree = validate_tree(&canister_id, &certificate, &tree);
            let mut valid_body = validate_body(&tree, &request_uri, &decoded_body_sha);

            if !encoding.is_none() && !valid_body {
                let body_sha = hash(response.body.as_slice());
                valid_body = validate_body(&tree, &request_uri, &body_sha);
            }

            let result = valid_tree && valid_body;
            let certified_response = match result {
                true => Some(Response {
                    status_code: response.status_code,
                    headers: Vec::new(),
                    body: response.body,
                }),
                false => None,
            };

            Ok(CertificationResult {
                passed: result,
                response: certified_response,
            })
        }
        _ => Ok(CertificationResult {
            passed: false,
            response: None,
        }),
    }
}

fn v2_verification(
    request: Request,
    response: Response,
    canister_id: &[u8],
    current_time_ns: u128,
    max_cert_time_offset_ns: u128,
    tree: Option<HashTree>,
    certificate: Option<Certificate>,
    expr_path: Option<Vec<String>>,
    expr_hash: Option<Sha256Digest>,
    certification: Option<Certification>,
    ic_public_key: &[u8],
) -> ResponseVerificationResult<CertificationResult> {
    let request_uri = request.get_uri()?;

    let (Some(expr_path), Some(expr_hash), Some(tree), Some(certificate)) = (expr_path, expr_hash, tree, certificate) else {
        return Ok(CertificationResult {
            passed: false,
            response: None,
        });
    };

    validate_certificate_time(&certificate, &current_time_ns, &max_cert_time_offset_ns)?;
    certificate.verify(&canister_id, &ic_public_key)?;

    if !validate_tree(&canister_id, &certificate, &tree)
        || !validate_expr_path(&expr_path, &request_uri, &tree)
    {
        return Ok(CertificationResult {
            passed: false,
            response: None,
        });
    };

    let Some(certification) = certification else {
        return Ok(CertificationResult {
            passed: validate_expr_hash(&expr_path, &expr_hash, &tree).is_some(),
            response: None,
        });
    };

    let request_hash = match &certification.request_certification {
        Some(request_certification) => Some(hash::request_hash(&request, request_certification)),
        None => None,
    };

    let body_hash = hash(&response.body);
    let response_headers =
        filter_response_headers(&response, &certification.response_certification);
    let response_headers_hash =
        hash::response_headers_hash(&response.status_code.into(), &response_headers);
    let response_hash = hash([response_headers_hash, body_hash].concat().as_slice());

    let are_hashes_valid = validate_hashes(
        &expr_hash,
        &request_hash,
        &response_hash,
        &expr_path,
        &tree,
        &certification,
    );

    Ok(CertificationResult {
        passed: are_hashes_valid,
        response: Some(Response {
            status_code: response.status_code,
            headers: response_headers.headers,
            body: response.body.clone(),
        }),
    })
}
