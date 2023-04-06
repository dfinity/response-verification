//! # Response Verification
//!
//! Response verification on the [Internet Computer](https://dfinity.org) is the process of
//! verifying that a canister response from a replica has gone through consensus with other replicas
//! hosting the same canister.
//!
//! This package encapsulates the protocol for such verification. It is used by the
//! [Service Worker](https://github.com/dfinity/ic/tree/master/typescript/service-worker) and
//! [ICX Proxy](https://github.com/dfinity/ic/tree/master/rs/boundary_node/icx_proxy) and may be
//! used by other implementations of the
//! [HTTP Gateway Protocol](https://internetcomputer.org/docs/current/references/ic-interface-spec/#http-gateway)
//! in the future.

#![deny(
    missing_docs,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links,
    rustdoc::private_intra_doc_links
)]

use crate::body::decode_body;
use crate::hash::{filter_response_headers, hash};
use crate::types::{CertificationResult, CertifiedResponse};
use crate::validation::{validate_expr_hash, validate_expr_path, VerifyCertificate};
use cbor::{certificate::CertificateToCbor, hash_tree::HashTreeToCbor, parse_cbor_string_array};
use certificate_header::CertificateHeader;
use ic_certification::hash_tree::Sha256Digest;
use ic_certification::{Certificate, HashTree};
use types::{Certification, Request, Response};
use validation::{validate_body, validate_certificate_time, validate_hashes, validate_tree};

pub mod cel;
pub mod error;
pub mod hash;
pub mod types;
pub use error::*;

mod body;
mod cbor;
mod certificate_header;
mod certificate_header_field;
mod test_utils;
mod validation;

/// The minimum verification version supported by this package.
pub const MIN_VERIFICATION_VERSION: u8 = 1;
/// The maximum verification version supported by this package.
pub const MAX_VERIFICATION_VERSION: u8 = 2;

/// The primary entry point for verifying a request and response pair. This will verify the response
/// with respect to the request, according the [Response Verification Spec]().
pub fn verify_request_response_pair(
    request: Request,
    response: Response,
    canister_id: &[u8],
    current_time_ns: u128,
    max_cert_time_offset_ns: u128,
    ic_public_key: &[u8],
    min_requested_verification_version: u8,
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
            let certificate_header = CertificateHeader::from(value.as_str())?;

            tree = certificate_header
                .tree
                .map(|tree| HashTree::from_cbor(&tree))
                .transpose()?;

            certificate = certificate_header
                .certificate
                .map(|certificate| Certificate::from_cbor(&certificate))
                .transpose()?;

            version = certificate_header
                .version
                .unwrap_or(MIN_VERIFICATION_VERSION);

            expr_path = certificate_header
                .expr_path
                .map(|expr_path| parse_cbor_string_array(&expr_path, "expr_path"))
                .transpose()?;
        }

        if name.eq_ignore_ascii_case("Ic-CertificateExpression") {
            certification = cel::cel_to_certification(value)?;
            expr_hash = Some(hash(value.as_bytes()));
        }

        if name.eq_ignore_ascii_case("Content-Encoding") {
            encoding = Some(value.into());
        }
    }

    if version < min_requested_verification_version {
        return Err(
            ResponseVerificationError::RequestedVerificationVersionMismatch {
                requested_version: version,
                min_requested_verification_version,
            },
        );
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
            certificate.verify(canister_id, ic_public_key)?;

            let request_uri = &request.get_uri()?;
            let decoded_body = decode_body(&response.body, &encoding)?;
            let decoded_body_sha = hash(decoded_body.as_slice());
            let valid_tree = validate_tree(canister_id, &certificate, &tree);
            let mut valid_body = validate_body(&tree, request_uri, &decoded_body_sha);

            if encoding.is_some() && !valid_body {
                let body_sha = hash(response.body.as_slice());
                valid_body = validate_body(&tree, request_uri, &body_sha);
            }

            let result = valid_tree && valid_body;
            let certified_response = match result {
                true => Some(CertifiedResponse {
                    status_code: None,
                    headers: Vec::new(),
                    body: response.body,
                }),
                false => None,
            };

            Ok(CertificationResult {
                passed: result,
                response: certified_response,
                verification_version: 1,
            })
        }
        _ => Ok(CertificationResult {
            passed: false,
            response: None,
            verification_version: 1,
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
            verification_version: 2,
        });
    };

    validate_certificate_time(&certificate, &current_time_ns, &max_cert_time_offset_ns)?;
    certificate.verify(canister_id, ic_public_key)?;

    if !validate_tree(canister_id, &certificate, &tree)
        || !validate_expr_path(&expr_path, &request_uri, &tree)
    {
        return Ok(CertificationResult {
            passed: false,
            response: None,
            verification_version: 2,
        });
    };

    let Some(certification) = certification else {
        return Ok(CertificationResult {
            passed: validate_expr_hash(&expr_path, &expr_hash, &tree).is_some(),
            response: None,
            verification_version: 2,
        });
    };

    let request_hash = certification
        .request_certification
        .as_ref()
        .map(|request_certification| hash::request_hash(&request, request_certification))
        .transpose()?;

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

    let response = match are_hashes_valid {
        true => Some(CertifiedResponse {
            status_code: Some(response.status_code),
            headers: response_headers.headers,
            body: response.body,
        }),
        false => None,
    };

    Ok(CertificationResult {
        passed: are_hashes_valid,
        response,
        verification_version: 2,
    })
}
