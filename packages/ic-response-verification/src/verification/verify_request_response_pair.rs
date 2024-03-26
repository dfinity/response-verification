use super::{body::decode_body, certificate_header::CertificateHeader};
use crate::{
    cel::{map_cel_ast, parse_cel_expression},
    error::{ResponseVerificationError, ResponseVerificationResult},
    types::{VerificationInfo, VerifiedResponse},
    validation::{
        validate_body, validate_expr_hash, validate_expr_path, validate_hashes, validate_tree,
    },
};
use ic_cbor::{parse_cbor_string_array, CertificateToCbor, HashTreeToCbor};
use ic_certificate_verification::VerifyCertificate;
use ic_certification::{hash_tree::Hash, Certificate, HashTree};
use ic_http_certification::{
    cel::{
        CelExpression, DefaultCelExpression, DefaultFullCelExpression,
        DefaultResponseOnlyCelExpression,
    },
    filter_response_headers, request_hash, response_headers_hash, HttpRequest, HttpResponse,
};
use ic_representation_independent_hash::hash;
use std::collections::HashMap;

/// The minimum verification version supported by this package.
pub const MIN_VERIFICATION_VERSION: u8 = 1;
/// The maximum verification version supported by this package.
pub const MAX_VERIFICATION_VERSION: u8 = 2;

/// The primary entry point for verifying a request and response pair. This will verify the response
/// with respect to the request, according the [Response Verification Spec]().
pub fn verify_request_response_pair(
    request: HttpRequest,
    response: HttpResponse,
    canister_id: &[u8],
    current_time_ns: u128,
    max_cert_time_offset_ns: u128,
    ic_public_key: &[u8],
    min_requested_verification_version: u8,
) -> ResponseVerificationResult<VerificationInfo> {
    let headers: HashMap<_, _> = response
        .headers
        .iter()
        .map(|(k, v)| (k.to_lowercase(), v.clone()))
        .collect();

    let encoding = headers
        .get("content-encoding")
        .map(|encoding| encoding.as_str());

    let Some(certificate_header) = headers.get("ic-certificate") else {
        return Err(ResponseVerificationError::MissingCertification);
    };

    let certificate_header = CertificateHeader::from(certificate_header)?;

    let Some(tree) = certificate_header
        .tree
        .map(|tree| HashTree::from_cbor(&tree))
        .transpose()?
    else {
        return Err(ResponseVerificationError::MissingTree);
    };

    let Some(certificate) = certificate_header
        .certificate
        .map(|certificate| Certificate::from_cbor(&certificate))
        .transpose()?
    else {
        return Err(ResponseVerificationError::MissingCertificate);
    };

    let version = certificate_header
        .version
        .unwrap_or(MIN_VERIFICATION_VERSION);

    match version {
        version if version < min_requested_verification_version => Err(
            ResponseVerificationError::RequestedVerificationVersionMismatch {
                requested_version: version,
                min_requested_verification_version,
            },
        ),
        1 => v1_verification(V1VerificationOpts {
            request,
            response,
            canister_id,
            current_time_ns,
            max_cert_time_offset_ns,
            tree,
            certificate,
            encoding,
            ic_public_key,
        }),
        2 => match headers.get("ic-certificateexpression") {
            Some(certificate_expression_header) => {
                let Some(expr_path) = certificate_header
                    .expr_path
                    .map(|expr_path| parse_cbor_string_array(&expr_path))
                    .transpose()?
                else {
                    return Err(ResponseVerificationError::MissingCertificateExpressionPath);
                };

                let cel_ast = parse_cel_expression(certificate_expression_header)?;
                let certification = map_cel_ast(&cel_ast)?;
                let expr_hash = hash(certificate_expression_header.as_bytes());

                v2_verification(V2VerificationOpts {
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
                })
            }
            None => Err(ResponseVerificationError::MissingCertification),
        },
        _ => Err(ResponseVerificationError::UnsupportedVerificationVersion {
            min_supported_version: MIN_VERIFICATION_VERSION,
            max_supported_version: MAX_VERIFICATION_VERSION,
            requested_version: version,
        }),
    }
}

struct V1VerificationOpts<'a> {
    request: HttpRequest,
    response: HttpResponse,
    canister_id: &'a [u8],
    current_time_ns: u128,
    max_cert_time_offset_ns: u128,
    tree: HashTree,
    certificate: Certificate,
    encoding: Option<&'a str>,
    ic_public_key: &'a [u8],
}

fn v1_verification(
    V1VerificationOpts {
        request,
        response,
        canister_id,
        current_time_ns,
        max_cert_time_offset_ns,
        tree,
        certificate,
        encoding,
        ic_public_key,
    }: V1VerificationOpts<'_>,
) -> ResponseVerificationResult<VerificationInfo> {
    certificate.verify(
        canister_id,
        ic_public_key,
        &current_time_ns,
        &max_cert_time_offset_ns,
    )?;

    let request_path = request.get_path()?;
    let decoded_body = decode_body(&response.body, encoding)?;
    let decoded_body_sha = hash(decoded_body.as_slice());

    if !validate_tree(canister_id, &certificate, &tree) {
        return Err(ResponseVerificationError::InvalidTree);
    }

    let mut valid_body = validate_body(&tree, &request_path, &decoded_body_sha);
    if encoding.is_some() && !valid_body {
        let body_sha = hash(response.body.as_slice());
        valid_body = validate_body(&tree, &request_path, &body_sha);
    }

    if !valid_body {
        return Err(ResponseVerificationError::InvalidResponseBody);
    }

    Ok(VerificationInfo {
        response: Some(VerifiedResponse {
            status_code: None,
            headers: Vec::new(),
            body: response.body,
        }),
        verification_version: 1,
    })
}

struct V2VerificationOpts<'a> {
    request: HttpRequest,
    response: HttpResponse,
    canister_id: &'a [u8],
    current_time_ns: u128,
    max_cert_time_offset_ns: u128,
    tree: HashTree,
    certificate: Certificate,
    expr_path: Vec<String>,
    expr_hash: Hash,
    certification: CelExpression<'a>,
    ic_public_key: &'a [u8],
}

fn v2_verification(
    V2VerificationOpts {
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
    }: V2VerificationOpts<'_>,
) -> ResponseVerificationResult<VerificationInfo> {
    let request_path = request.get_path()?;

    certificate.verify(
        canister_id,
        ic_public_key,
        &current_time_ns,
        &max_cert_time_offset_ns,
    )?;

    if !validate_tree(canister_id, &certificate, &tree) {
        return Err(ResponseVerificationError::InvalidTree);
    }

    validate_expr_path(&expr_path, &request_path, &tree)?;

    let (request_certification, response_certification) = match &certification {
        CelExpression::Default(DefaultCelExpression::Skip) => {
            return match validate_expr_hash(&expr_path, &expr_hash, &tree).is_some() {
                true => Ok(VerificationInfo {
                    response: None,
                    verification_version: 2,
                }),
                false => Err(ResponseVerificationError::InvalidExpressionPath),
            };
        }
        CelExpression::Default(DefaultCelExpression::ResponseOnly(
            DefaultResponseOnlyCelExpression { response },
        )) => (None, response),
        CelExpression::Default(DefaultCelExpression::Full(DefaultFullCelExpression {
            request,
            response,
        })) => (Some(request), response),
    };

    let request_hash = request_certification
        .as_ref()
        .map(|request_certification| request_hash(&request, request_certification))
        .transpose()?;

    let body_hash = hash(&response.body);
    let response_headers = filter_response_headers(&response, response_certification);
    let response_headers_hash =
        response_headers_hash(&response.status_code.into(), &response_headers);
    let response_hash = hash([response_headers_hash, body_hash].concat().as_slice());

    let are_hashes_valid = validate_hashes(
        &expr_hash,
        &request_hash,
        &response_hash,
        &expr_path,
        &tree,
        &certification,
    );

    match are_hashes_valid {
        true => Ok(VerificationInfo {
            response: Some(VerifiedResponse {
                status_code: Some(response.status_code),
                headers: response_headers.headers,
                body: response.body,
            }),
            verification_version: 2,
        }),
        false => Err(ResponseVerificationError::InvalidResponseHashes),
    }
}
